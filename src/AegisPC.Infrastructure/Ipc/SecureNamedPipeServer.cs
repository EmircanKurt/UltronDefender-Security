using System;
using System.IO;
using System.IO.Pipes;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Infrastructure.Ipc
{
    public class IpcSecureMessage
    {
        public string Command { get; set; } = string.Empty;
        public string Payload { get; set; } = string.Empty;
        public long TimestampUtcTicks { get; set; } = DateTime.UtcNow.Ticks;
        public string Nonce { get; set; } = Guid.NewGuid().ToString("N");
        public string SignatureHmac { get; set; } = string.Empty;
    }

    public class SecureNamedPipeServer : IDisposable
    {
        private readonly string _pipeName;
        private readonly byte[] _hmacKey;
        private CancellationTokenSource? _cts;
        private Task? _serverTask;
        private readonly object _lifecycleLock = new();
        private bool _disposed;
        // Nonce replay cache — tracks used nonces to prevent replay attacks within the 30s window
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _usedNonces = new();

        public SecureNamedPipeServer(string pipeName, string sharedSecret)
        {
            _pipeName = pipeName;
            _hmacKey = SHA256.HashData(Encoding.UTF8.GetBytes(sharedSecret));
        }

        public void Start(Func<IpcSecureMessage, string> messageHandler)
        {
            ArgumentNullException.ThrowIfNull(messageHandler);
            lock (_lifecycleLock)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (_cts != null) throw new InvalidOperationException("IPC server has already started.");
                _cts = new CancellationTokenSource();
                var token = _cts.Token;
                _serverTask = Task.Run(async () =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        try
                        {
                            using var server = NamedPipeServerStreamAcl.Create(
                            _pipeName,
                            PipeDirection.InOut,
                            1,
                            PipeTransmissionMode.Message,
                            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                            4096,
                            4096,
                            BoundedPipeProtocol.CreateLocalSecurity(allowAuthenticatedUsers: false));

                            await server.WaitForConnectionAsync(token);

                            using var reader = new StreamReader(server, Encoding.UTF8);
                            using var writer = new StreamWriter(server, Encoding.UTF8) { AutoFlush = true };
                            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                            deadline.CancelAfter(TimeSpan.FromSeconds(30));

                            var rawJson = await BoundedPipeProtocol.ReadCommandAsync(reader, deadline.Token);
                            if (!string.IsNullOrEmpty(rawJson))
                            {
                                var msg = JsonSerializer.Deserialize<IpcSecureMessage>(rawJson);
                                if (msg != null && ValidateMessage(msg))
                                {
                                    var response = messageHandler(msg);
                                    await writer.WriteLineAsync(response.AsMemory(), deadline.Token);
                                }
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            Trace.WriteLine("IPC listener cancelled or client response timed out.");
                        }
                        catch (Exception exception)
                        {
                            Trace.WriteLine($"IPC listener failed: {exception}");
                            try { await Task.Delay(1000, token); }
                            catch (OperationCanceledException) { break; }
                        }
                    }
                }, token);
            }
        }

        private bool ValidateMessage(IpcSecureMessage msg)
        {
            if (msg.Command == null || msg.Command.Length is 0 or > 128 || msg.Command.Contains('|') ||
                msg.Payload == null || msg.Payload.Length > BoundedPipeProtocol.MaximumCommandCharacters ||
                msg.Nonce == null || !Guid.TryParseExact(msg.Nonce, "N", out _) ||
                msg.SignatureHmac == null || msg.SignatureHmac.Length != 44 ||
                msg.TimestampUtcTicks < DateTime.MinValue.Ticks || msg.TimestampUtcTicks > DateTime.MaxValue.Ticks)
                return false;

            // Replay attack prevention: Max 30 seconds drift
            var msgTime = new DateTime(msg.TimestampUtcTicks, DateTimeKind.Utc);
            if (Math.Abs((DateTime.UtcNow - msgTime).TotalSeconds) > 30) return false;

            // Periodically clean expired nonces (older than 60s)
            foreach (var kvp in _usedNonces)
            {
                if ((DateTime.UtcNow - kvp.Value).TotalSeconds > 60)
                    _usedNonces.TryRemove(kvp.Key, out _);
            }

            string contentToSign = $"{msg.Command}|{msg.Payload}|{msg.TimestampUtcTicks}|{msg.Nonce}";
            using var hmac = new HMACSHA256(_hmacKey);
            byte[] expectedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(contentToSign));
            Span<byte> suppliedHash = stackalloc byte[32];
            if (!Convert.TryFromBase64String(msg.SignatureHmac, suppliedHash, out var written) || written != 32 ||
                !CryptographicOperations.FixedTimeEquals(suppliedHash, expectedHash))
                return false;

            // Only authenticated messages may consume replay-cache capacity.
            if (_usedNonces.Count >= 4096) return false;
            return _usedNonces.TryAdd(msg.Nonce, DateTime.UtcNow);
        }

        public void Dispose()
        {
            lock (_lifecycleLock)
            {
                if (_disposed) return;
                _disposed = true;
                _cts?.Cancel();
                var source = _cts;
                if (_serverTask != null)
                    _ = _serverTask.ContinueWith(_ => source?.Dispose(), CancellationToken.None,
                        TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                else source?.Dispose();
            }
        }
    }
}
