using System;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.ServiceContracts.IpcMessages;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.IPC
{
    public class NamedPipeServer : BackgroundService
    {
        private readonly ILogger<NamedPipeServer> _logger;
        private readonly IBackgroundProtectionService _protectionService;
        private readonly IRansomwareProtectionEngine _ransomwareEngine;
        private readonly IScanCoordinatorService? _scanCoordinator;
        private readonly DateTime _startTime = DateTime.UtcNow;
        private int _totalThreatsBlocked24h = 0;
        private DateTime? _lastThreatTime;

        private readonly ConcurrentDictionary<Guid, StreamWriter> _connectedClients = new();

        public const string PipeName = "UltronDefender_IPC";

        public NamedPipeServer(
            ILogger<NamedPipeServer> logger,
            IBackgroundProtectionService protectionService,
            IRansomwareProtectionEngine ransomwareEngine,
            IScanCoordinatorService? scanCoordinator = null)
        {
            _logger = logger;
            _protectionService = protectionService;
            _ransomwareEngine = ransomwareEngine;
            _scanCoordinator = scanCoordinator;

            // Wire up real-time events to broadcast to IPC clients
            _protectionService.OnThreatDetected += OnThreatDetected;
            _ransomwareEngine.OnRansomwareAttemptDetected += OnRansomwareAttemptDetected;
        }

        private void OnThreatDetected(SecurityFinding finding)
        {
            _lastThreatTime = DateTime.UtcNow;
            Interlocked.Increment(ref _totalThreatsBlocked24h);

            var threatNotification = new ThreatNotification
            {
                FilePath = finding.ObjectPath,
                ProcessName = "FileSystemMonitor",
                ProcessId = 0,
                ThreatName = finding.Title,
                RiskLevel = finding.RiskLevel,
                ActionTaken = "Karantinaya Alındı",
                Details = finding.Description,
                DetectedAt = finding.CreatedAt
            };

            BroadcastMessage("Threat", threatNotification);
        }

        private void OnRansomwareAttemptDetected(object? sender, RansomwareAlertEventArgs e)
        {
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
                try
                {
                    kvp.Value.WriteLine(line);
                    kvp.Value.Flush();
                }
                catch
                {
                    _connectedClients.TryRemove(kvp.Key, out _);
                }
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("AegisPC IPC Server starting on pipe: {PipeName}", PipeName);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var pipeServer = new NamedPipeServerStream(
                        PipeName,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous);

                    await pipeServer.WaitForConnectionAsync(stoppingToken);
                    _ = HandleClientConnectionAsync(pipeServer, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error accepting IPC connection.");
                    await Task.Delay(1000, stoppingToken);
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
            using (var writer = new StreamWriter(pipeServer, Encoding.UTF8) { AutoFlush = true })
            {
                _connectedClients[clientId] = writer;

                try
                {
                    while (!stoppingToken.IsCancellationRequested && pipeServer.IsConnected)
                    {
                        var line = await reader.ReadLineAsync(stoppingToken);
                        if (line == null) break;

                        if (string.IsNullOrWhiteSpace(line)) continue;

                        try
                        {
                            var command = JsonSerializer.Deserialize<ServiceCommand>(line);
                            if (command != null)
                            {
                                await ProcessCommandAsync(command, writer);
                            }
                        }
                        catch (Exception cmdEx)
                        {
                            _logger.LogWarning(cmdEx, "Failed to parse command from client {ClientId}", clientId);
                        }
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogTrace(ex, "Client connection ended: {ClientId}", clientId);
                }
                finally
                {
                    _connectedClients.TryRemove(clientId, out _);
                    _logger.LogInformation("IPC Client disconnected: {ClientId}", clientId);
                }
            }
        }

        private async Task ProcessCommandAsync(ServiceCommand command, StreamWriter writer)
        {
            switch (command.CommandType)
            {
                case ServiceCommandType.GetStatus:
                    var status = BuildCurrentStatus();
                    var statusJson = JsonSerializer.Serialize(status);
                    await writer.WriteLineAsync($"Status:{statusJson}");
                    break;

                case ServiceCommandType.EnableProtection:
                    _protectionService.StartProtection();
                    await writer.WriteLineAsync($"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.DisableProtection:
                    _protectionService.StopProtection();
                    await writer.WriteLineAsync($"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.EnableRansomwareShield:
                    _ransomwareEngine.StartShield();
                    await writer.WriteLineAsync($"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.DisableRansomwareShield:
                    _ransomwareEngine.StopShield();
                    await writer.WriteLineAsync($"Status:{JsonSerializer.Serialize(BuildCurrentStatus())}");
                    break;

                case ServiceCommandType.StartScan:
                    if (_scanCoordinator != null)
                    {
                        _ = _scanCoordinator.StartScanAsync(ScanType.Quick);
                    }
                    break;

                case ServiceCommandType.StopScan:
                    _scanCoordinator?.CancelScan();
                    break;
            }
        }

        private ProtectionStatus BuildCurrentStatus()
        {
            return new ProtectionStatus
            {
                IsServiceRunning = true,
                IsRealTimeEnabled = _protectionService.IsProtectionActive,
                IsRansomwareShieldEnabled = _ransomwareEngine.IsShieldActive,
                IsNetworkProtectionEnabled = false,
                IsAmsiEnabled = true,
                LastThreatTime = _lastThreatTime,
                TotalThreatsBlocked24h = _totalThreatsBlocked24h,
                ServiceUptime = DateTime.UtcNow - _startTime,
                ProtectionLevel = _protectionService.IsProtectionActive && _ransomwareEngine.IsShieldActive ? "Tam Koruma" : "Kısmi Koruma"
            };
        }
    }
}
