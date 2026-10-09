using System;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Infrastructure.Ipc;
using AegisPC.ServiceContracts.IpcMessages;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.IPC
{
    public partial class NamedPipeServer : BackgroundService
    {
        private readonly ILogger<NamedPipeServer> _logger;
        private readonly IBackgroundProtectionService _protectionService;
        private readonly IRealTimeProtectionEngine _realTimeProtectionEngine;
        private readonly IRansomwareProtectionEngine _ransomwareEngine;
        private readonly SettingsService _settingsService;
        private readonly IScanCoordinatorService? _scanCoordinator;
        private readonly AegisPC.Service.Network.INetworkProtectionService? _networkProtectionService;
        private readonly IAmsiScanService? _amsiScanService;
        private readonly IScanResourceManager? _resourceManager;
        private readonly IExclusionService? _exclusionService;
        private readonly ProtectionCommandLifecycle _fileProtectionLifecycle;
        private readonly IEtwPreExecProtectionService? _processInspection;
        private readonly AegisPC.Service.RealTime.EtwProcessMonitor? _processTelemetry;
        private readonly AegisPC.Service.RealTime.EtwImageLoadMonitor? _imageTelemetry;
        private readonly AegisPC.Service.DriverBridge.IKernelBridge? _kernelBridge;
        private readonly AegisPC.Contracts.Devices.IDeviceInventoryMonitor? _devices;
        private readonly IQuarantineService? _vault;
        private readonly RansomwareShieldActivation? _shieldActivation;
        private readonly AegisPC.Contracts.Detection.IDetectionHub? _detectionHub;
        private readonly AegisPC.Contracts.Protection.IBehaviorObservationSource? _behaviorObservations;
        private readonly AegisPC.Service.Workers.UltronObservationWorker? _aiObservationWorker;
        private readonly AegisPC.Service.RealTime.EtwFileIoObservationWorker? _fileIoObservationWorker;
        private readonly DateTime _startTime = DateTime.UtcNow;
        private int _totalThreatsBlocked24h = 0;
        private DateTime _threatCounterWindowStart = DateTime.UtcNow;
        private DateTime? _lastThreatTime;

        private sealed class ServiceSettingsPatch
        {
            public bool? EnableAutoQuarantine { get; set; }
            public int? AutoQuarantineThreshold { get; set; }
            public bool? ScanScheduleEnabled { get; set; }
            public int? ScheduledScanHour { get; set; }
            public int? ScheduledScanIntervalHours { get; set; }
            public bool? IdleScanEnabled { get; set; }
            public int? IdleScanThresholdMinutes { get; set; }
            public int? IdleScanIntervalHours { get; set; }
            public bool? SkipIdleScanOnBattery { get; set; }
            public AegisPC.Core.Enums.ScanResourceMode? ScanResourceMode { get; set; }
            public bool? RefreshExclusions { get; set; }
        }

        private readonly ConcurrentDictionary<Guid, PipeClientConnection> _connectedClients = new();
        private readonly SemaphoreSlim _connectionSlots = new(16, 16);

        public const string PipeName = "UltronDefender_IPC";

        public NamedPipeServer(
            ILogger<NamedPipeServer> logger,
            IBackgroundProtectionService protectionService,
            IRealTimeProtectionEngine realTimeProtectionEngine,
            IRansomwareProtectionEngine ransomwareEngine,
            SettingsService settingsService,
            IScanCoordinatorService? scanCoordinator = null,
            AegisPC.Service.Network.INetworkProtectionService? networkProtectionService = null,
            IAmsiScanService? amsiScanService = null,
            IScanResourceManager? resourceManager = null,
            IEtwPreExecProtectionService? etwPreExecService = null,
            AegisPC.Service.DriverBridge.IKernelBridge? kernelBridge = null,
            AegisPC.Service.RealTime.EtwProcessMonitor? processMonitor = null,
            AegisPC.Service.RealTime.EtwImageLoadMonitor? imageLoadMonitor = null,
            IExclusionService? exclusionService = null,
            AegisPC.Contracts.Devices.IDeviceInventoryMonitor? devices = null,
            IQuarantineService? vault = null,
            RansomwareShieldActivation? shieldActivation = null,
            AegisPC.Contracts.Detection.IDetectionHub? detectionHub = null,
            AegisPC.Contracts.Protection.IBehaviorObservationSource? behaviorObservations = null,
            AegisPC.Service.Workers.UltronObservationWorker? aiObservationWorker = null,
            AegisPC.Service.RealTime.EtwFileIoObservationWorker? fileIoObservationWorker = null,
            AegisPC.Contracts.Protection.IRemoteProtectionMonitor? remoteObservation = null,
            AegisPC.Contracts.Protection.IWirelessProtectionMonitor? wirelessObservation = null,
            AegisPC.Service.Workers.PassiveSecurityObservationWorker? passiveWorker = null)
        {
            _logger = logger;
            _shieldActivation = shieldActivation;
            _detectionHub = detectionHub;
            _behaviorObservations = behaviorObservations;
            _aiObservationWorker = aiObservationWorker;
            _fileIoObservationWorker = fileIoObservationWorker;
            _remoteObservation = remoteObservation;
            _wirelessObservation = wirelessObservation;
            _passiveWorker = passiveWorker;
            _protectionService = protectionService;
            _realTimeProtectionEngine = realTimeProtectionEngine;
            _ransomwareEngine = ransomwareEngine;
            _settingsService = settingsService;
            _scanCoordinator = scanCoordinator;
            _networkProtectionService = networkProtectionService;
            _amsiScanService = amsiScanService;
            _resourceManager = resourceManager;
            _exclusionService = exclusionService;
            _processInspection = etwPreExecService;
            _processTelemetry = processMonitor;
            _imageTelemetry = imageLoadMonitor;
            _kernelBridge = kernelBridge;
            _devices = devices;
            _vault = vault;
            if (_devices != null) _devices.SnapshotChanged += OnDeviceSnapshotChanged;
            _fileProtectionLifecycle = ProtectionCommandLifecycle.Create(realTimeProtectionEngine, protectionService,
                logger, etwPreExecService, settingsService.GetSetting("EnableExperimentalKernelBridge", false) ? kernelBridge : null,
                processMonitor, imageLoadMonitor, devices);
            _fileProtectionPause = new TimedFileProtectionPause(
                () => _settingsService.Current.FileProtectionPause, SavePauseIntentAsync,
                enabled => _fileProtectionLifecycle.SetEnabledAsync(_settingsService, enabled),
                () => _protectionService.IsProtectionActive && _realTimeProtectionEngine.IsRunning);

            // Wire up real-time events to broadcast to IPC clients
            _protectionService.OnThreatDetected += OnThreatDetected;
            _realTimeProtectionEngine.OnThreatDetected += OnThreatDetected;
            _ransomwareEngine.OnRansomwareAttemptDetected += OnRansomwareAttemptDetected;
        }

        private void OnThreatDetected(SecurityFinding finding)
        {
            ResetThreatCounterIfExpired();
            _lastThreatTime = DateTime.UtcNow;
            // A resolved finding can have been dismissed or excluded. Its status
            // alone does not prove quarantine or a successful containment action.

            var threatNotification = new ThreatNotification
            {
                FilePath = finding.ObjectPath,
                SHA256 = finding.SHA256 ?? string.Empty,
                SoftwareClass = finding.SoftwareClass,
                SoftwareClassification = finding.SoftwareClassification,
                RuleSetVersion = finding.RuleSetVersion,
                InspectionComplete = finding.InspectionComplete,
                CoverageLimitations = finding.CoverageLimitations.ToArray(),
                PolicyBypassed = finding.IsAllowlisted,
                HasIndependentMalwareEvidence = finding.HasIndependentMalwareEvidence,
                ProcessName = "FileSystemMonitor",
                ProcessId = 0,
                ThreatName = finding.Title,
                RiskLevel = finding.RiskLevel,
                ActionTaken = finding.IsAllowlisted
                    ? "Kullanıcı istisnası; karantina sonucu bu olayda doğrulanmadı"
                    : finding.Status == FindingStatus.Resolved
                        ? "Bulgu kapatıldı; karantina sonucu bu olayda doğrulanmadı"
                        : "Güvenlik bulgusu kaydedildi (inceleme veya müdahale bekliyor)",
                Details = finding.Description,
                DetectedAt = finding.CreatedAt
            };

            BroadcastMessage("Threat", threatNotification);
        }

        private void OnRansomwareAttemptDetected(object? sender, RansomwareAlertEventArgs e)
        {
            ResetThreatCounterIfExpired();
            _lastThreatTime = DateTime.UtcNow;
            // The legacy event has no verifiable action receipt. A mutable boolean is not containment evidence.

            var threatNotification = new ThreatNotification
            {
                FilePath = e.OffendingFilePath,
                ProcessName = "RansomwareShield",
                ProcessId = 0,
                ThreatName = "RansomwareObservation",
                // A heuristic score and a file-locking PID do not independently prove malware.
                RiskLevel = RiskLevel.Suspicious,
                IsObservationOnly = true,
                ActionTaken = "Sezgisel gözlem kaydedildi; zararlı yazılım, saldırgan süreç ve engelleme doğrulanmadı",
                Details = e.DetectionReason,
                DetectedAt = e.Timestamp
            };

            BroadcastMessage("Threat", threatNotification);
        }

        public void BroadcastMessage<T>(string typeName, T payload)
        {
            var json = JsonSerializer.Serialize(payload);
            var line = $"{typeName}:{json}";

            foreach (var kvp in _connectedClients)
            {
                // Global service events may contain another logged-on user's full paths.
                // Standard users receive aggregate status, not other users' threat payloads.
                if (typeName == "Threat" && !kvp.Value.MayReceiveMachineThreats) continue;
                var clientId = kvp.Key;
                if (!kvp.Value.TrySend(line))
                {
                    _logger.LogWarning("Disconnecting slow IPC client {ClientId}: outbound queue is full.", clientId);
                    if (_connectedClients.TryRemove(clientId, out var removed)) removed.Dispose();
                }
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("AegisPC IPC Server starting on pipe: {PipeName}", PipeName);
            using var pauseLifetime = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            var pauseRecovery = _fileProtectionPause.RunRecoveryAsync(_logger, pauseLifetime.Token);
            using var heartbeat = new Timer(_ =>
            {
                if (stoppingToken.IsCancellationRequested) return;
                try { BroadcastMessage("Status", BuildCurrentStatus()); }
                catch (Exception exception) { _logger.LogWarning(exception, "Protection status heartbeat failed."); }
            }, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));

            try
            {
            while (!stoppingToken.IsCancellationRequested)
            {
                NamedPipeServerStream? pendingPipe = null;
                var slotAcquired = false;
                try
                {
                    await _connectionSlots.WaitAsync(stoppingToken).ConfigureAwait(false);
                    slotAcquired = true;
                    pendingPipe = NamedPipeServerStreamAcl.Create(
                        PipeName,
                        PipeDirection.InOut,
                        16,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous,
                        0, 0,
                        BoundedPipeProtocol.CreateLocalSecurity());

                    await pendingPipe.WaitForConnectionAsync(stoppingToken);
                    _ = HandleClientConnectionAsync(pendingPipe, stoppingToken);
                    pendingPipe = null; // Ownership and the reserved slot transfer to the handler.
                    slotAcquired = false;
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error accepting IPC connection.");
                    if (!stoppingToken.IsCancellationRequested)
                        await Task.Delay(1000, stoppingToken);
                }
                finally
                {
                    pendingPipe?.Dispose();
                    if (slotAcquired) _connectionSlots.Release();
                }
            }

            }
            finally
            {
                pauseLifetime.Cancel();
                await pauseRecovery.ConfigureAwait(false);
            }
            _logger.LogInformation("AegisPC IPC Server stopped.");
        }

        private async Task HandleClientConnectionAsync(NamedPipeServerStream pipeServer, CancellationToken stoppingToken)
        {
            var clientId = Guid.NewGuid();
            _logger.LogInformation("IPC Client connected: {ClientId}", clientId);

            using (pipeServer)
            using (var reader = new StreamReader(pipeServer, Encoding.UTF8))
            {
                var writer = new StreamWriter(pipeServer, Encoding.UTF8, 4096, leaveOpen: true) { AutoFlush = true };
                using var client = new PipeClientConnection(writer, pipeServer, _logger, stoppingToken);
                _connectedClients[clientId] = client;

                try
                {
                    while (!stoppingToken.IsCancellationRequested && pipeServer.IsConnected)
                    {
                        var line = await BoundedPipeProtocol.ReadCommandAsync(reader, stoppingToken);
                        if (line == null) break;

                        if (string.IsNullOrWhiteSpace(line)) continue;

                        try
                        {
                            if (ServiceCommandParser.TryParse(line, out var command) && command != null)
                            {
                                await ProcessCommandAsync(command, client, pipeServer);
                            }
                            else
                            {
                                _logger.LogWarning("Rejected malformed IPC command from {ClientId}.", clientId);
                                await SendResponseAsync(client, "Error:Invalid command envelope.");
                            }
                        }
                        catch (Exception cmdEx)
                        {
                            _logger.LogWarning(cmdEx, "Failed to process command from client {ClientId}", clientId);
                            await SendResponseAsync(client, "Error:Command failed; protection state may be partial.");
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    _logger.LogDebug("IPC client read cancelled or frame timed out: {ClientId}", clientId);
                }
                catch (Exception ex)
                {
                    _logger.LogTrace(ex, "Client connection ended: {ClientId}", clientId);
                }
                finally
                {
                    _connectedClients.TryRemove(clientId, out _);
                    _connectionSlots.Release();
                    _logger.LogInformation("IPC Client disconnected: {ClientId}", clientId);
                }
            }
        }

        private static Task SendResponseAsync(PipeClientConnection client, string response) => client.SendAsync(response);

        private async Task ProcessCommandAsync(ServiceCommand command, PipeClientConnection client, NamedPipeServerStream pipeServer)
        {
            if (IsVaultOrInventoryCommand(command.CommandType))
            {
                await ProcessAuthorizedDataCommandAsync(command, client, pipeServer).ConfigureAwait(false);
                return;
            }
            using var verifiedCaller = AuthenticatedPipeCaller.Capture(pipeServer);
            string callerIdentity = verifiedCaller.Identity.Name;

            bool isAuthorized = ServiceControlCommandAuthorization.IsAllowed(command.CommandType, verifiedCaller.IsAdministrator);
            client.MayReceiveMachineThreats = verifiedCaller.IsAdministrator;

            _logger.LogInformation("AUDIT IPC: Command {CommandType} from {Caller} (Authorized: {IsAuthorized})",
                command.CommandType, callerIdentity, isAuthorized);

            if (!isAuthorized)
            {
                _logger.LogWarning("SECURITY AUDIT: Unauthorized IPC control command {CommandType} denied for caller: {Caller}",
                    command.CommandType, callerIdentity);
                await SendResponseAsync(client, $"Error:Unauthorized command type {command.CommandType}. Administrators only.");
                return;
            }

            switch (command.CommandType)
            {
                case ServiceCommandType.GetStatus:
                    var status = BuildCurrentStatus(command.RequestId);
                    var statusJson = JsonSerializer.Serialize(status);
                    await SendResponseAsync(client, $"Status:{statusJson}");
                    break;

                case ServiceCommandType.EnableProtection:
                    await _fileProtectionPause.SetManualEnabledAsync(enabled: true);
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.DisableProtection:
                    await _fileProtectionPause.SetManualEnabledAsync(enabled: false);
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.PauseFileProtection:
                    await ProcessPauseAsync(command, client);
                    break;

                case ServiceCommandType.EnableRansomwareShield:
                    if (_shieldActivation != null) await _shieldActivation.StartAsync();
                    else _ransomwareEngine.StartShield();
                    _settingsService.Current.IsRansomwareShieldEnabled = true;
                    await _settingsService.SaveAsync();
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.DisableRansomwareShield:
                    if (_shieldActivation != null) await _shieldActivation.StopAsync();
                    else _ransomwareEngine.StopShield();
                    _settingsService.Current.IsRansomwareShieldEnabled = false;
                    await _settingsService.SaveAsync();
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.EnableNetworkProtection:
                    _networkProtectionService?.Start();
                    _settingsService.Current.IsNetworkProtectionEnabled = true;
                    await _settingsService.SaveAsync();
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.DisableNetworkProtection:
                    _networkProtectionService?.Stop();
                    _settingsService.Current.IsNetworkProtectionEnabled = false;
                    await _settingsService.SaveAsync();
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.EnableUltronAi:
                case ServiceCommandType.DisableUltronAi:
                    await SetUltronAiReviewEnabledAsync(command.CommandType == ServiceCommandType.EnableUltronAi);
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus(command.RequestId))}");
                    break;

                case ServiceCommandType.StartScan:
                    if (_scanCoordinator != null)
                    {
                        _resourceManager?.SetMode(_settingsService.Current.ScanResourceMode);
                        _ = _scanCoordinator.StartScanAsync(ScanType.Quick);
                    }
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.StopScan:
                    _scanCoordinator?.CancelScan();
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.UpdateSettings:
                    if (!string.IsNullOrWhiteSpace(command.Payload))
                    {
                        var patch = JsonSerializer.Deserialize<ServiceSettingsPatch>(command.Payload);
                        if (patch?.RefreshExclusions == true)
                        {
                            if (_exclusionService is not IExclusionRefreshService refresher)
                                throw new InvalidOperationException("Exclusion refresh capability is unavailable.");
                            await refresher.ReloadAsync(CancellationToken.None);
                            // In-flight results and caches must not survive a changed exclusion policy.
                            AegisPC.Security.DetectionPolicyRevision.Invalidate();
                        }
                        if (patch?.EnableAutoQuarantine is bool enableAutoQuarantine)
                            _settingsService.Current.EnableAutoQuarantine = enableAutoQuarantine;
                        if (patch?.AutoQuarantineThreshold is int threshold)
                            _settingsService.Current.AutoQuarantineThreshold = Math.Clamp(threshold, 0, 100);
                        if (patch?.ScanScheduleEnabled is bool scanScheduleEnabled)
                        {
                            _settingsService.Current.ScanScheduleEnabled = scanScheduleEnabled;
                            _protectionService.SetScheduledScansEnabled(scanScheduleEnabled);
                        }
                        if (patch?.ScheduledScanHour is int scanHour)
                            _settingsService.Current.ScheduledScanHour = Math.Clamp(scanHour, 0, 23);
                        if (patch?.ScheduledScanIntervalHours is int scanInterval)
                            _settingsService.Current.ScheduledScanIntervalHours = Math.Clamp(scanInterval, 0, 24);
                        if (patch?.IdleScanEnabled is bool idleEnabled)
                            _settingsService.Current.IdleScanEnabled = idleEnabled;
                        if (patch?.IdleScanThresholdMinutes is int idleMinutes)
                            _settingsService.Current.IdleScanThresholdMinutes = Math.Clamp(idleMinutes, 1, 240);
                        if (patch?.IdleScanIntervalHours is int idleHours)
                            _settingsService.Current.IdleScanIntervalHours = Math.Clamp(idleHours, 1, 168);
                        if (patch?.SkipIdleScanOnBattery is bool skipOnBattery)
                            _settingsService.Current.SkipIdleScanOnBattery = skipOnBattery;
                        if (patch?.ScanResourceMode is AegisPC.Core.Enums.ScanResourceMode resourceMode && Enum.IsDefined(resourceMode))
                        {
                            _settingsService.Current.ScanResourceMode = resourceMode;
                            _resourceManager?.SetMode(resourceMode);
                        }
                        await _settingsService.SaveAsync();
                    }
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;
            }
        }

        private bool IsAuthorizedCommand(NamedPipeServerStream pipeServer, ServiceCommandType commandType)
        {
            if (commandType == ServiceCommandType.GetStatus)
            {
                return true;
            }

            try
            {
                bool isAuthorized = false;
                pipeServer.RunAsClient(() =>
                {
                    using var current = WindowsIdentity.GetCurrent();
                    if (current == null)
                    {
                        return;
                    }

                    if (current.IsSystem)
                    {
                        isAuthorized = true;
                        return;
                    }

                    var principal = new WindowsPrincipal(current);
                    if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                    {
                        isAuthorized = true;
                        return;
                    }

                    // WindowsPrincipal, UAC ile filtrelenmiş (deny-only) yönetici SID'lerini
                    // doğru şekilde reddeder. Ham grup listesini kabul etmek yetki yükseltme açığıdır.
                });

                return isAuthorized;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "IPC yetkilendirme kontrolü başarısız oldu.");
                return false;
            }
        }

        private ProtectionStatus BuildCurrentStatus(Guid requestId = default)
        {
            ResetThreatCounterIfExpired();
            var coverage = (_realTimeProtectionEngine as IRealTimeCoverageProvider)?.CaptureCoverage();
            int processLost = _processTelemetry?.EventsLost ?? -1;
            int imageLost = _imageTelemetry?.EventsLost ?? -1;
            var health = ProtectionHealthSampler.Capture(_settingsService.Current.IsFileProtectionEnabled,
                _protectionService.IsProtectionActive && _realTimeProtectionEngine.IsRunning, coverage,
                _processTelemetry?.IsRunning == true && _processInspection?.IsEtwSubscribed == true,
                _imageTelemetry?.IsRunning == true,
                processLost < 0 || imageLost < 0 ? -1 : (long)processLost + imageLost,
                _fileProtectionLifecycle.IsHealthy, _kernelBridge?.IsDriverConnected == true,
                _ransomwareEngine.IsShieldActive);
            health.DeviceInventoryActive = _devices?.IsRunning == true;
            AddPassiveHealth(health);
            var observations = _behaviorObservations?.CaptureHealth();
            health.BehaviorObservationActive = _aiObservationWorker?.IsObservationActive == true;
            health.PendingBehaviorEvents = observations?.Pending ?? 0;
            health.BehaviorEventsLost = (observations?.Dropped ?? 0) + (observations?.Invalid ?? 0) +
                (_fileIoObservationWorker?.DroppedEvents ?? 0) + Math.Max(0, _fileIoObservationWorker?.OsEventsLost ?? 0);
            health.FileIoAttributionActive = _fileIoObservationWorker?.IsObservationActive == true;
            health.UnattributedFileWrites = _fileIoObservationWorker?.UnattributedWrites ?? 0;
            health.SignedThreatIntelProvisioned = AegisPC.Security.ThreatIntelligence.AuthoritativeThreatCatalog.Count > 2;
            if (_settingsService.GetSetting("IsUltronAiEnabled", true) &&
                (!health.BehaviorObservationActive || !health.FileIoAttributionActive || health.BehaviorEventsLost > 0 ||
                    health.UnattributedFileWrites > 0))
            {
                if (health.State != ProtectionHealthState.Stopped) health.State = ProtectionHealthState.Degraded;
                health.Limitations = health.Limitations.Append("AI event review or file-writer attribution is unavailable/partial; native actions remain gated.").ToArray();
            }
            var inventory = _devices?.CurrentSnapshot;
            bool inventoryFresh = inventory != null && inventory.CapturedAtUtc != default && DateTime.UtcNow >= inventory.CapturedAtUtc &&
                DateTime.UtcNow - inventory.CapturedAtUtc <= TimeSpan.FromSeconds(75);
            health.DeviceInventoryComplete = inventory?.IsComplete == true && inventoryFresh;
            health.ObservedDeviceInterfaces = _devices?.CurrentSnapshot.Devices.Count ?? 0;
            health.DeviceInventoryCapturedAtUtc = _devices?.CurrentSnapshot.CapturedAtUtc;
            var ransomCoverage = (_ransomwareEngine as IRansomwareCoverageProvider)?.CaptureRansomwareCoverage();
            if (_settingsService.Current.IsRansomwareShieldEnabled &&
                (ransomCoverage == null || ransomCoverage.WatcherCount == 0 || ransomCoverage.HasUnresolvedGap))
            {
                if (health.State != ProtectionHealthState.Stopped) health.State = ProtectionHealthState.Degraded;
                health.Limitations = health.Limitations.Append("Ransomware observation roots or event continuity are incomplete.").ToArray();
            }
            var amsiObserved = _amsiScanService as IAmsiObservationProvider;
            health.AmsiLastNativeScanUtc = amsiObserved?.LastNativeScanUtc;
            health.AmsiContentScanningActive = _amsiScanService?.IsAmsiSupported == true && amsiObserved?.LastNativeRequestCompleted == true &&
                amsiObserved.LastNativeScanUtc is DateTime nativeTime && nativeTime >= _startTime && nativeTime <= DateTime.UtcNow;
            if (!health.AmsiContentScanningActive)
                health.Limitations = health.Limitations.Append("A successfully completed native AMSI content request has not been observed for this service instance.").ToArray();
            if (_settingsService.Current.IsFileProtectionEnabled &&
                (!health.DeviceInventoryActive || !health.DeviceInventoryComplete))
            {
                health.State = ProtectionHealthState.Degraded;
                health.Limitations = health.Limitations.Append("Device discovery is unavailable or partial; firmware safety is not verified.").ToArray();
            }
            return new ProtectionStatus
            {
                RequestId = requestId,
                Health = health,
                IsServiceRunning = true,
                IsRealTimeEnabled = _protectionService.IsProtectionActive && _realTimeProtectionEngine.IsRunning,
                SupportsTimedFileProtectionPause = true,
                FileProtectionPause = _settingsService.Current.FileProtectionPause,
                IsUltronAiEnabled = _detectionHub?.RegisteredDetectors
                    .OfType<AegisPC.Security.Detection.Detectors.UltronAiDetectorPlugin>()
                    .FirstOrDefault()?.IsReviewEnabled,
                IsRansomwareShieldEnabled = _ransomwareEngine.IsShieldActive,
                RansomwareProtectedFolderCount = ransomCoverage?.WatcherCount,
                RansomwareCanaryFileCount = _ransomwareEngine.CanaryFileCount,
                RansomwareConfirmedContainments = null,
                IsNetworkProtectionEnabled = _networkProtectionService?.IsRunning == true && _networkProtectionService.IsDnsSinkholeActive,
                IsAmsiEnabled = health.AmsiContentScanningActive,
                ScanScheduleEnabled = _settingsService.Current.ScanScheduleEnabled,
                ScheduledScanHour = _settingsService.Current.ScheduledScanHour,
                ScheduledScanIntervalHours = _settingsService.Current.ScheduledScanIntervalHours,
                IdleScanEnabled = _settingsService.Current.IdleScanEnabled,
                IdleScanThresholdMinutes = _settingsService.Current.IdleScanThresholdMinutes,
                IdleScanIntervalHours = _settingsService.Current.IdleScanIntervalHours,
                SkipIdleScanOnBattery = _settingsService.Current.SkipIdleScanOnBattery,
                ScanResourceMode = _settingsService.Current.ScanResourceMode,
                EnableAutoQuarantine = _settingsService.Current.EnableAutoQuarantine,
                AutomaticContainmentAvailable = AegisPC.Security.UltronAI.ProtectionNativePilotPolicy.AutomaticContainmentAvailable,
                AutomaticContainmentReason = AegisPC.Security.UltronAI.ProtectionNativePilotPolicy.ReasonCode,
                AutoQuarantineThreshold = _settingsService.Current.AutoQuarantineThreshold,
                LastThreatTime = _lastThreatTime,
                TotalThreatsBlocked24h = _totalThreatsBlocked24h,
                ServiceUptime = DateTime.UtcNow - _startTime,
                ProtectionLevel = health.State switch
                {
                    ProtectionHealthState.Healthy => "Gözlenen kullanıcı modu koruma etkin",
                    ProtectionHealthState.Recovering => "Kapsam yeniden inceleniyor",
                    ProtectionHealthState.Stopped => "Dosya koruması durduruldu",
                    _ => "Kısıtlı kullanıcı modu koruma"
                }
            };
        }

        private void ResetThreatCounterIfExpired()
        {
            var now = DateTime.UtcNow;
            if (now - _threatCounterWindowStart < TimeSpan.FromHours(24)) return;

            _threatCounterWindowStart = now;
            Interlocked.Exchange(ref _totalThreatsBlocked24h, 0);
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            _protectionService.OnThreatDetected -= OnThreatDetected;
            _realTimeProtectionEngine.OnThreatDetected -= OnThreatDetected;
            _ransomwareEngine.OnRansomwareAttemptDetected -= OnRansomwareAttemptDetected;
            return base.StopAsync(cancellationToken);
        }

        public override void Dispose()
        {
            _protectionService.OnThreatDetected -= OnThreatDetected;
            _realTimeProtectionEngine.OnThreatDetected -= OnThreatDetected;
            _ransomwareEngine.OnRansomwareAttemptDetected -= OnRansomwareAttemptDetected;
            base.Dispose();
        }
    }
}
