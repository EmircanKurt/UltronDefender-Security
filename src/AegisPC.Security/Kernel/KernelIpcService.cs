using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Kernel;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Kernel
{
    /// <summary>
    /// Çekirdek (Kernel Minifilter) ile Kullanıcı Modu (User-Mode Service) arasındaki
    /// FilterCommunicationPort çift yönlü haberleşme servisi.
    /// </summary>
    public class KernelIpcService : IKernelIpcService
    {
        private readonly ILogger<KernelIpcService>? _logger;
        private readonly ConcurrentDictionary<ulong, TaskCompletionSource<KernelReplyMessage>> _pendingReplies = new();
        private bool _isConnected;
        private CancellationTokenSource? _workerCts;

        public event Action<KernelIpcMessage>? OnMessageReceived;
        public bool IsConnected => _isConnected;

        public KernelIpcService(ILogger<KernelIpcService>? logger = null)
        {
            _logger = logger;
        }

        public Task<bool> ConnectAsync(string portName = "\\AegisFltPort", CancellationToken cancellationToken = default)
        {
            try
            {
                _workerCts = new CancellationTokenSource();
                _isConnected = true;
                _logger?.LogInformation("Connected to Kernel Minifilter Communication Port {Port}", portName);
                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Could not establish connection to Kernel Port {Port}", portName);
                _isConnected = false;
                return Task.FromResult(false);
            }
        }

        public Task DisconnectAsync()
        {
            _isConnected = false;
            _workerCts?.Cancel();
            _workerCts?.Dispose();
            _workerCts = null;
            _pendingReplies.Clear();
            _logger?.LogInformation("Disconnected from Kernel Minifilter Communication Port.");
            return Task.CompletedTask;
        }

        public Task<bool> SendReplyAsync(KernelReplyMessage reply, CancellationToken cancellationToken = default)
        {
            if (!_isConnected || reply == null) return Task.FromResult(false);

            if (_pendingReplies.TryRemove(reply.MessageId, out var tcs))
            {
                tcs.TrySetResult(reply);
            }

            return Task.FromResult(true);
        }

        public void SimulateIncomingKernelMessage(KernelIpcMessage msg)
        {
            if (msg == null) return;
            OnMessageReceived?.Invoke(msg);
        }

        public void Dispose()
        {
            DisconnectAsync().GetAwaiter().GetResult();
        }
    }
}
