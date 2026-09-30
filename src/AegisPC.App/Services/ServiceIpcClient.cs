using System;
using System.Collections.Concurrent;
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
        private readonly ConcurrentDictionary<Guid, TaskCompletionSource<ProtectionStatus>> _pendingStatusRequests = new();

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

        /// <summary>
        /// Returns a disconnected state when no pipe exists; otherwise waits up to five seconds for this
        /// request's authenticated-service reply and throws on timeout or connection loss rather than returning stale cache.
        /// </summary>
        public async Task<ProtectionStatus> GetStatusAsync()
        {
            if (!IsConnected)
            {
                return new ProtectionStatus
                {
                    ProtectionLevel = "Hizmet Bağlantısı Yok",
                    IsServiceRunning = false,
                    IsRealTimeEnabled = false,
                    IsRansomwareShieldEnabled = false,
                    IsNetworkProtectionEnabled = false,
                    IsAmsiEnabled = false,
                    ServiceUptime = TimeSpan.Zero
                };
            }

            var requestId = Guid.NewGuid();
            var completion = new TaskCompletionSource<ProtectionStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!_pendingStatusRequests.TryAdd(requestId, completion))
                throw new InvalidOperationException("Could not reserve a unique IPC status request identity.");
            try
            {
                await SendCommandAsync(new ServiceCommand
                {
                    CommandType = ServiceCommandType.GetStatus,
                    Timestamp = DateTime.UtcNow,
                    RequestId = requestId
                });
                return await completion.Task.WaitAsync(TimeSpan.FromSeconds(5), _cts.Token);
            }
            catch (TimeoutException exception)
            {
                throw new TimeoutException("Protection service did not acknowledge the matching status request; the installed service may require an update.", exception);
            }
            finally
            {
                _pendingStatusRequests.TryRemove(requestId, out _);
            }
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
                                if (status.RequestId != Guid.Empty)
                                {
                                    if (!_pendingStatusRequests.TryRemove(status.RequestId, out var pending))
                                    {
                                        Trace.WriteLine("Ignoring an unmatched or expired IPC status response.");
                                        continue;
                                    }
                                    _lastKnownStatus = status;
                                    pending.TrySetResult(status);
                                    StatusChanged?.Invoke(status);
                                    continue;
                                }
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
                    FailPendingStatusRequests(new IOException("Protection service IPC connection ended before a matching status response."));
                    if (!_cts.Token.IsCancellationRequested) _ = ConnectAsync();
                }
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
            _cts.Cancel();
            FailPendingStatusRequests(new ObjectDisposedException(nameof(ServiceIpcClient)));
            _pipeClient?.Dispose();
            // Semaphores remain managed until outstanding async users release them.
        }

        private void FailPendingStatusRequests(Exception exception)
        {
            foreach (var request in _pendingStatusRequests)
            {
                if (_pendingStatusRequests.TryRemove(request.Key, out var completion))
                    completion.TrySetException(exception);
            }
        }
    }
}
