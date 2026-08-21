using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
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

        public bool IsConnected => _pipeClient?.IsConnected ?? false;
        public ProtectionStatus? LastKnownStatus => _lastKnownStatus;

        public event Action<ThreatNotification>? ThreatDetected;
        public event Action<ProtectionStatus>? StatusChanged;

        public async Task ConnectAsync()
        {
            if (IsConnected) return;

            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    _pipeClient = new NamedPipeClientStream(".", "UltronDefender_IPC", PipeDirection.InOut, PipeOptions.Asynchronous);
                    await _pipeClient.ConnectAsync(3000, _cts.Token);
                    _ = ListenForMessagesAsync();
                    
                    // Request status right after connect
                    _ = SendCommandAsync(new ServiceCommand
                    {
                        CommandType = ServiceCommandType.GetStatus,
                        Timestamp = DateTime.UtcNow
                    });
                    break;
                }
                catch (Exception)
                {
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

        public async Task SendCommandAsync(ServiceCommand command)
        {
            if (!IsConnected || _pipeClient == null) return;

            await _writeLock.WaitAsync(_cts.Token);
            try
            {
                var json = JsonSerializer.Serialize(command);
                var buffer = Encoding.UTF8.GetBytes(json + "\n");
                await _pipeClient.WriteAsync(buffer, 0, buffer.Length, _cts.Token);
                await _pipeClient.FlushAsync(_cts.Token);
            }
            catch
            {
                // Disconnected or write error
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

            return _lastKnownStatus ?? new ProtectionStatus
            {
                ProtectionLevel = IsConnected ? "Bağlı (Durum Alınıyor)" : "Hizmet Bağlantısı Yok",
                IsServiceRunning = IsConnected,
                IsRealTimeEnabled = false,
                IsRansomwareShieldEnabled = false,
                IsNetworkProtectionEnabled = false,
                IsAmsiEnabled = true,
                ServiceUptime = TimeSpan.Zero
            };
        }

        private async Task ListenForMessagesAsync()
        {
            try
            {
                using var reader = new StreamReader(_pipeClient!, Encoding.UTF8, false, 4096, leaveOpen: true);
                while (IsConnected && !_cts.Token.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(_cts.Token);
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
                    catch { }
                }
            }
            catch { }
            finally
            {
                if (!_cts.Token.IsCancellationRequested)
                {
                    _pipeClient?.Dispose();
                    _pipeClient = null;
                    _ = ConnectAsync();
                }
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _cts.Cancel();
            _pipeClient?.Dispose();
            _writeLock.Dispose();
            _isDisposed = true;
        }
    }
}
