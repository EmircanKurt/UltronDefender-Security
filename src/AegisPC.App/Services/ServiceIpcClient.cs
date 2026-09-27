using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Security.Principal;
using AegisPC.Infrastructure.Ipc;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.Services
{
    public class ServiceIpcClient : IServiceIpcClient, IDisposable
    {
        private NamedPipeClientStream? _pipeClient;
        private readonly CancellationTokenSource _cts = new();
        private bool _isDisposed;
        private ProtectionStatus? _lastKnownStatus;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly SemaphoreSlim _connectLock = new(1, 1);

        public bool IsConnected => _pipeClient?.IsConnected ?? false;
        public ProtectionStatus? LastKnownStatus => _lastKnownStatus;

        public event Action<ThreatNotification>? ThreatDetected;
        public event Action<ProtectionStatus>? StatusChanged;

        public async Task ConnectAsync()
        {
            if (IsConnected || _isDisposed) return;
            try { await _connectLock.WaitAsync(_cts.Token); }
            catch (OperationCanceledException) { return; }
            try
            {
            if (IsConnected || _isDisposed) return;
            while (!_cts.Token.IsCancellationRequested)
            {
                NamedPipeClientStream? candidate = null;
                try
                {
                    candidate = new NamedPipeClientStream(".", "UltronDefender_IPC", PipeDirection.InOut,
                        PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
                    await candidate.ConnectAsync(3000, _cts.Token);
                    _cts.Token.ThrowIfCancellationRequested();
                    if (!PipeServiceIdentity.IsExpectedService(candidate, "AegisPC Protection Service"))
                        throw new UnauthorizedAccessException("IPC server does not belong to the installed protection service.");
                    _pipeClient = candidate;
                    candidate = null;
                    _ = ListenForMessagesAsync(_pipeClient);
                    
                    // Request status right after connect
                    _ = SendCommandAsync(new ServiceCommand
                    {
                        CommandType = ServiceCommandType.GetStatus,
                        Timestamp = DateTime.UtcNow
                    });
                    break;
                }
                catch (Exception exception)
                {
                    candidate?.Dispose();
                    Trace.WriteLine($"IPC connection failed: {exception.Message}");
                    // Retry periodically in background
                    try
                    {
                        await Task.Delay(3000, _cts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
            }
            finally { _connectLock.Release(); }
        }

        public async Task SendCommandAsync(ServiceCommand command)
        {
            var pipe = _pipeClient;
            if (!IsConnected || pipe == null || _isDisposed) return;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            deadline.CancelAfter(TimeSpan.FromSeconds(5));
            try { await _writeLock.WaitAsync(deadline.Token); }
            catch (OperationCanceledException) { return; }
            try
            {
                var json = JsonSerializer.Serialize(command);
                if (json.Length > BoundedPipeProtocol.MaximumCommandCharacters)
                    throw new InvalidDataException("IPC command exceeds the permitted size.");
                var buffer = Encoding.UTF8.GetBytes(json + "\n");
                await pipe.WriteAsync(buffer, 0, buffer.Length, deadline.Token);
                await pipe.FlushAsync(deadline.Token);
            }
            catch (Exception exception)
            {
                Trace.WriteLine($"IPC write failed: {exception.Message}");
                pipe.Dispose();
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task<ProtectionStatus> GetStatusAsync()
        {
            if (IsConnected)
            {
                await SendCommandAsync(new ServiceCommand
                {
                    CommandType = ServiceCommandType.GetStatus,
                    Timestamp = DateTime.UtcNow
                });
            }

            return (IsConnected ? _lastKnownStatus : null) ?? new ProtectionStatus
            {
                ProtectionLevel = IsConnected ? "Bağlı (Durum Alınıyor)" : "Hizmet Bağlantısı Yok",
                IsServiceRunning = IsConnected,
                IsRealTimeEnabled = false,
                IsRansomwareShieldEnabled = false,
                IsNetworkProtectionEnabled = false,
                IsAmsiEnabled = false,
                ServiceUptime = TimeSpan.Zero
            };
        }

        private async Task ListenForMessagesAsync(NamedPipeClientStream pipe)
        {
            try
            {
                using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
                while (pipe.IsConnected && !_cts.Token.IsCancellationRequested)
                {
                    var line = await BoundedPipeProtocol.ReadCommandAsync(reader, _cts.Token, 262_144);
                    if (line == null) break;

                    if (string.IsNullOrWhiteSpace(line)) continue;

                    try
                    {
                        if (line.StartsWith("Threat:", StringComparison.OrdinalIgnoreCase))
                        {
                            var json = line.Substring(7);
                            var threat = JsonSerializer.Deserialize<ThreatNotification>(json);
                            if (threat != null) ThreatDetected?.Invoke(threat);
                        }
                        else if (line.StartsWith("Status:", StringComparison.OrdinalIgnoreCase))
                        {
                            var json = line.Substring(7);
                            var status = JsonSerializer.Deserialize<ProtectionStatus>(json);
                            if (status != null)
                            {
                                _lastKnownStatus = status;
                                StatusChanged?.Invoke(status);
                            }
                        }
                    }
                    catch (Exception exception) { Trace.WriteLine($"Invalid IPC response: {exception.Message}"); }
                }
            }
            catch (Exception exception) { Trace.WriteLine($"IPC listener ended: {exception.Message}"); }
            finally
            {
                pipe.Dispose();
                if (ReferenceEquals(_pipeClient, pipe))
                {
                    _pipeClient = null;
                    _lastKnownStatus = null;
                    if (!_cts.Token.IsCancellationRequested) _ = ConnectAsync();
                }
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
            _cts.Cancel();
            _pipeClient?.Dispose();
            // Semaphores remain managed until outstanding async users release them.
        }
    }
}
