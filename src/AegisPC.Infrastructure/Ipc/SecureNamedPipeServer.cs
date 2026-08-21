using System;
using System.IO;
using System.IO.Pipes;
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

        public SecureNamedPipeServer(string pipeName, string sharedSecret)
        {
            _pipeName = pipeName;
            _hmacKey = SHA256.HashData(Encoding.UTF8.GetBytes(sharedSecret));
        }

        public void Start(Func<IpcSecureMessage, string> messageHandler)
        {
            _cts = new CancellationTokenSource();
            Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    try
                    {
                        var pipeSecurity = new PipeSecurity();
                        var currentUser = WindowsIdentity.GetCurrent().User;
                        if (currentUser != null)
                        {
                            pipeSecurity.AddAccessRule(new PipeAccessRule(currentUser, PipeAccessRights.ReadWrite, AccessControlType.Allow));
                        }
                        var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                        pipeSecurity.AddAccessRule(new PipeAccessRule(adminSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));

                        using var server = NamedPipeServerStreamAcl.Create(
                            _pipeName,
                            PipeDirection.InOut,
                            NamedPipeServerStream.MaxAllowedServerInstances,
                            PipeTransmissionMode.Message,
                            PipeOptions.Asynchronous,
                            4096,
                            4096,
                            pipeSecurity);

                        await server.WaitForConnectionAsync(_cts.Token);

                        using var reader = new StreamReader(server, Encoding.UTF8);
                        using var writer = new StreamWriter(server, Encoding.UTF8) { AutoFlush = true };

                        string? rawJson = await reader.ReadLineAsync();
                        if (!string.IsNullOrEmpty(rawJson))
                        {
                            var msg = JsonSerializer.Deserialize<IpcSecureMessage>(rawJson);
                            if (msg != null && ValidateMessage(msg))
                            {
                                string response = messageHandler(msg);
                                await writer.WriteLineAsync(response);
                            }
                        }
                    }
                    catch { }
                }
            }, _cts.Token);
        }

        private bool ValidateMessage(IpcSecureMessage msg)
        {
            // Replay attack prevention: Max 30 seconds drift
            var msgTime = new DateTime(msg.TimestampUtcTicks, DateTimeKind.Utc);
            if (Math.Abs((DateTime.UtcNow - msgTime).TotalSeconds) > 30) return false;

            string contentToSign = $"{msg.Command}|{msg.Payload}|{msg.TimestampUtcTicks}|{msg.Nonce}";
            using var hmac = new HMACSHA256(_hmacKey);
            byte[] expectedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(contentToSign));
            string expectedSig = Convert.ToBase64String(expectedHash);

            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(msg.SignatureHmac),
                Encoding.UTF8.GetBytes(expectedSig));
        }

        public void Dispose()
        {
            _cts?.Cancel();
        }
    }
}
