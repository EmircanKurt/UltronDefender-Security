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
    public class NamedPipeServer : BackgroundService
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
            IExclusionService? exclusionService = null)
        {
            _logger = logger;
            _protectionService = protectionService;
            _realTimeProtectionEngine = realTimeProtectionEngine;
            _ransomwareEngine = ransomwareEngine;
            _settingsService = settingsService;
            _scanCoordinator = scanCoordinator;
            _networkProtectionService = networkProtectionService;
            _amsiScanService = amsiScanService;
            _resourceManager = resourceManager;
            _exclusionService = exclusionService;
            _fileProtectionLifecycle = ProtectionCommandLifecycle.Create(realTimeProtectionEngine, protectionService,
                logger, etwPreExecService, kernelBridge, processMonitor, imageLoadMonitor);

            // Wire up real-time events to broadcast to IPC clients
            _protectionService.OnThreatDetected += OnThreatDetected;
            _realTimeProtectionEngine.OnThreatDetected += OnThreatDetected;
            _ransomwareEngine.OnRansomwareAttemptDetected += OnRansomwareAttemptDetected;
        }

        private void OnThreatDetected(SecurityFinding finding)
        {
            ResetThreatCounterIfExpired();
            _lastThreatTime = DateTime.UtcNow;
            if (finding.Status == FindingStatus.Resolved)
                Interlocked.Increment(ref _totalThreatsBlocked24h);

            var threatNotification = new ThreatNotification
            {
                FilePath = finding.ObjectPath,
                ProcessName = "FileSystemMonitor",
                ProcessId = 0,
                ThreatName = finding.Title,
                RiskLevel = finding.RiskLevel,
                ActionTaken = finding.Status == FindingStatus.Resolved
                    ? "Karantinaya Alındı"
                    : "Tespit Edildi (müdahale bekliyor)",
                Details = finding.Description,
                DetectedAt = finding.CreatedAt
            };

            BroadcastMessage("Threat", threatNotification);
        }

        private void OnRansomwareAttemptDetected(object? sender, RansomwareAlertEventArgs e)
        {
            ResetThreatCounterIfExpired();
            _lastThreatTime = DateTime.UtcNow;
            Interlocked.Increment(ref _totalThreatsBlocked24h);

            var threatNotification = new ThreatNotification
            {
                FilePath = e.OffendingFilePath,
                ProcessName = "RansomwareShield",
                ProcessId = 0,
                ThreatName = "RansomwareActivity",
                RiskLevel = RiskLevel.ConfirmedMalicious,
                ActionTaken = "Süreç Durduruldu / Dosya İzolasyonu",
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
            string callerIdentity = "Anonymous";
            try
            {
                pipeServer.RunAsClient(() =>
                {
                    using var id = WindowsIdentity.GetCurrent();
                    callerIdentity = id?.Name ?? "Anonymous";
                });
            }
            catch (Exception ex)
            {
                _logger.LogTrace(ex, "Could not impersonate pipe client for identity extraction.");
            }

            bool isAuthorized = IsAuthorizedCommand(pipeServer, command.CommandType);
            client.MayReceiveMachineThreats = IsAuthorizedCommand(pipeServer, ServiceCommandType.EnableProtection);

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
                    var status = BuildCurrentStatus();
                    var statusJson = JsonSerializer.Serialize(status);
                    await SendResponseAsync(client, $"Status:{statusJson}");
                    break;

                case ServiceCommandType.EnableProtection:
                    await _fileProtectionLifecycle.SetEnabledAsync(_settingsService, enabled: true);
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.DisableProtection:
                    await _fileProtectionLifecycle.SetEnabledAsync(_settingsService, enabled: false);
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.EnableRansomwareShield:
                    _ransomwareEngine.StartShield();
                    _settingsService.Current.IsRansomwareShieldEnabled = true;
                    await _settingsService.SaveAsync();
                    await SendResponseAsync(client, $"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.DisableRansomwareShield:
                    _ransomwareEngine.StopShield();
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

        private ProtectionStatus BuildCurrentStatus()
        {
            ResetThreatCounterIfExpired();
            return new ProtectionStatus
            {
                IsServiceRunning = true,
                IsRealTimeEnabled = _protectionService.IsProtectionActive && _realTimeProtectionEngine.IsRunning,
                IsRansomwareShieldEnabled = _ransomwareEngine.IsShieldActive,
                IsNetworkProtectionEnabled = _networkProtectionService?.IsRunning ?? _settingsService.Current.IsNetworkProtectionEnabled,
                IsAmsiEnabled = _amsiScanService?.IsAmsiSupported ?? false,
                ScanScheduleEnabled = _settingsService.Current.ScanScheduleEnabled,
                ScheduledScanHour = _settingsService.Current.ScheduledScanHour,
                ScheduledScanIntervalHours = _settingsService.Current.ScheduledScanIntervalHours,
                IdleScanEnabled = _settingsService.Current.IdleScanEnabled,
                IdleScanThresholdMinutes = _settingsService.Current.IdleScanThresholdMinutes,
                IdleScanIntervalHours = _settingsService.Current.IdleScanIntervalHours,
                SkipIdleScanOnBattery = _settingsService.Current.SkipIdleScanOnBattery,
                ScanResourceMode = _settingsService.Current.ScanResourceMode,
                EnableAutoQuarantine = _settingsService.Current.EnableAutoQuarantine,
                AutoQuarantineThreshold = _settingsService.Current.AutoQuarantineThreshold,
                LastThreatTime = _lastThreatTime,
                TotalThreatsBlocked24h = _totalThreatsBlocked24h,
                ServiceUptime = DateTime.UtcNow - _startTime,
                ProtectionLevel = _protectionService.IsProtectionActive &&
                                  _realTimeProtectionEngine.IsRunning &&
                                  _ransomwareEngine.IsShieldActive && _fileProtectionLifecycle.IsHealthy
                    ? "Tam Koruma"
                    : "Kısmi Koruma"
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
