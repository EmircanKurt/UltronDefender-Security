using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Kernel;
using AegisPC.Security.Kernel;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class KernelMinifilterTests : IDisposable
    {
        private readonly string _sandboxDir;

        public KernelMinifilterTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "Aegis_KernelTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public void Test_KernelTelemetryEngine_FiltersPagingIoNoise()
        {
            var engine = new KernelMinifilterTelemetryEngine();
            bool eventFired = false;

            engine.OnTelemetryReceived += evt => eventFired = true;

            // Ingest paging I/O event
            engine.IngestKernelEvent(new KernelFileTelemetryEvent
            {
                OperationType = MinifilterOperationType.PreWrite,
                IsPagingIo = true,
                NtDevicePath = @"\Device\HarddiskVolume3\pagefile.sys"
            });

            Assert.False(eventFired, "Paging I/O noise must be filtered out.");

            // Ingest user file event
            engine.IngestKernelEvent(new KernelFileTelemetryEvent
            {
                OperationType = MinifilterOperationType.PreCreate,
                IsPagingIo = false,
                CanonicalDosPath = @"C:\Users\PC\Downloads\invoice.exe"
            });

            Assert.True(eventFired, "Real user file event must be ingested.");
        }

        [Fact]
        public async Task Test_KernelIpcService_ConnectAndSimulateMessageFraming()
        {
            using var ipc = new KernelIpcService();
            bool connected = await ipc.ConnectAsync("\\AegisTestPort");
            Assert.True(connected);
            Assert.True(ipc.IsConnected);

            KernelIpcMessage? received = null;
            ipc.OnMessageReceived += msg => received = msg;

            var testMsg = new KernelIpcMessage
            {
                MessageId = 1001,
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 4040,
                FilePath = @"C:\Temp\threat.exe"
            };

            ipc.SimulateIncomingKernelMessage(testMsg);

            Assert.NotNull(received);
            Assert.Equal(1001ul, received.MessageId);
            Assert.Equal(4040, received.ProcessId);

            var reply = new KernelReplyMessage
            {
                MessageId = 1001,
                NtStatus = 0xC0000022,
                GatingStatus = KernelGatingStatus.BlockedAccessDenied
            };

            bool sent = await ipc.SendReplyAsync(reply);
            Assert.True(sent);
        }

        [Fact]
        public async Task Test_KernelGatingEngine_BlocksMaliciousFile_ReturnsAccessDenied()
        {
            var gatingEngine = new KernelGatingEngine();
            var malFile = Path.Combine(_sandboxDir, "malware_blocked.bat");
            await File.WriteAllTextAsync(malFile, "REM AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182");

            var request = new KernelIpcMessage
            {
                MessageId = 5001,
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 1234,
                FilePath = malFile,
                TimeoutMs = 500
            };

            var decision = await gatingEngine.EvaluatePreOpDecisionAsync(request);

            Assert.True(decision.IsBlocked);
            Assert.Equal(0xC0000022u, decision.NtStatus); // STATUS_ACCESS_DENIED
            Assert.Equal(KernelGatingStatus.BlockedAccessDenied, decision.Status);
            Assert.True(decision.RiskScore >= 90);
        }

        [Fact]
        public async Task Test_KernelGatingEngine_AllowsBenignFile_ReturnsSuccess()
        {
            var gatingEngine = new KernelGatingEngine();
            var cleanFile = Path.Combine(_sandboxDir, "clean_document.txt");
            await File.WriteAllTextAsync(cleanFile, "Hello world, clean file.");

            var request = new KernelIpcMessage
            {
                MessageId = 5002,
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 1234,
                FilePath = cleanFile,
                TimeoutMs = 500
            };

            var decision = await gatingEngine.EvaluatePreOpDecisionAsync(request);

            Assert.False(decision.IsBlocked);
            Assert.Equal(0x00000000u, decision.NtStatus); // STATUS_SUCCESS
            Assert.Equal(KernelGatingStatus.Allowed, decision.Status);
        }
    }
}
