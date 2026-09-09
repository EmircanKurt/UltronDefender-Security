using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Contracts.Kernel;
using AegisPC.Security.Kernel;
using AegisPC.Security.SelfDefense;
using Xunit;

namespace AegisPC.Tests
{
    /// <summary>
    /// AegisFilter Kernel Minifilter Sürücüsü ve Sürücü Köprüsü (KernelBridge) test paketi.
    /// Sürücü yükleme/boşaltma, Pre-Operation engelleme (STATUS_ACCESS_DENIED),
    /// Paging I/O gürültü filtreleme ve çift yönlü çekirdek IPC mesajlaşmasını test eder.
    /// </summary>
    [Collection("SequentialDiskTests")]
    public class KernelDriverTest : IDisposable
    {
        private readonly string _sandboxDir;

        public KernelDriverTest()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "Aegis_KernelDriverTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);
        }

        [Fact]
        public void KernelDriver_LoadAndUnloadCommands_FormatCorrectlyAndReportStatus()
        {
            // 1. Sürücü yükleme komut biçimi ve SelfHeal doğrulaması
            string driverName = SelfHealManager.DefaultDriverName;
            Assert.Equal("AegisFilter", driverName);

            // 2. Unload girişiminin TamperDetector tarafından yakalanma testi
            string unloadCmd = $"fltmc.exe unload {driverName}";
            bool isTamper = TamperDetector.CheckTamperPattern(
                "cmd.exe",
                unloadCmd,
                out var tamperType,
                out var targetAsset,
                out var ruleName);

            Assert.True(isTamper, "fltmc unload AegisFilter sürücü boşaltma girişimi engellenmelidir.");
            Assert.Equal(TamperType.DriverUnloadTamper, tamperType);
            Assert.Contains("AegisFilter", targetAsset);
            Assert.Contains("TAMPER-01", ruleName);
        }

        [Fact]
        public async Task KernelPreOp_Interception_BlocksMaliciousExecution_ReturnsAccessDenied()
        {
            var gatingEngine = new KernelGatingEngine();
            var malFile = Path.Combine(_sandboxDir, "ransom_payload.bat");
            await File.WriteAllTextAsync(malFile, "REM AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182");

            var request = new KernelIpcMessage
            {
                MessageId = 7001,
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 4444,
                FilePath = malFile,
                TimeoutMs = 500
            };

            var decision = await gatingEngine.EvaluatePreOpDecisionAsync(request);

            Assert.True(decision.IsBlocked, "Zararlı dosya PreCreate aşamasında engellenmelidir.");
            Assert.Equal(0xC0000022u, decision.NtStatus); // STATUS_ACCESS_DENIED
            Assert.Equal(KernelGatingStatus.BlockedAccessDenied, decision.Status);
            Assert.True(decision.RiskScore >= 90);
        }

        [Fact]
        public async Task KernelPreOp_Interception_AllowsBenignFile_ReturnsSuccess()
        {
            var gatingEngine = new KernelGatingEngine();
            var cleanFile = Path.Combine(_sandboxDir, "normal_document.docx");
            await File.WriteAllTextAsync(cleanFile, "Clean benign document content for test.");

            var request = new KernelIpcMessage
            {
                MessageId = 7002,
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 1111,
                FilePath = cleanFile,
                TimeoutMs = 500
            };

            var decision = await gatingEngine.EvaluatePreOpDecisionAsync(request);

            Assert.False(decision.IsBlocked, "Temiz dosya PreCreate aşamasında engellenmemelidir.");
            Assert.Equal(0x00000000u, decision.NtStatus); // STATUS_SUCCESS
            Assert.Equal(KernelGatingStatus.Allowed, decision.Status);
        }

        [Fact]
        public void KernelMinifilter_NoiseFilter_DiscardsPagingIoAndIngestsUserFiles()
        {
            var engine = new KernelMinifilterTelemetryEngine();
            int receivedEvents = 0;

            engine.OnTelemetryReceived += evt => receivedEvents++;

            // 1. Paging I/O olayı (pagefile.sys / swap gürültüsü elenmeli)
            engine.IngestKernelEvent(new KernelFileTelemetryEvent
            {
                OperationType = MinifilterOperationType.PreWrite,
                IsPagingIo = true,
                NtDevicePath = @"\Device\HarddiskVolume3\pagefile.sys"
            });

            Assert.Equal(0, receivedEvents);

            // 2. Gerçek kullanıcı dosyası oluşturma olayı (alınmalı)
            engine.IngestKernelEvent(new KernelFileTelemetryEvent
            {
                OperationType = MinifilterOperationType.PreCreate,
                IsPagingIo = false,
                CanonicalDosPath = @"C:\Users\PC\Downloads\cryptolocker.exe"
            });

            Assert.Equal(1, receivedEvents);
        }

        [Fact]
        public async Task KernelBridge_IpcMessaging_BidirectionalFraming_SimulatedMode()
        {
            using var ipc = new KernelIpcService();
            bool connected = await ipc.ConnectAsync("\\AegisTestPort");
            Assert.True(connected);
            Assert.True(ipc.IsConnected);
            Assert.Equal(KernelDriverStatus.SimulatedMode, ipc.DriverStatus);

            KernelIpcMessage? capturedMessage = null;
            ipc.OnMessageReceived += msg => capturedMessage = msg;

            var incoming = new KernelIpcMessage
            {
                MessageId = 9901,
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 8888,
                FilePath = @"C:\Windows\Temp\malicious_dropper.exe"
            };

            ipc.SimulateIncomingKernelMessage(incoming);

            Assert.NotNull(capturedMessage);
            Assert.Equal(9901ul, capturedMessage.MessageId);
            Assert.Equal(8888, capturedMessage.ProcessId);
            Assert.Equal(@"C:\Windows\Temp\malicious_dropper.exe", capturedMessage.FilePath);

            var reply = new KernelReplyMessage
            {
                MessageId = 9901,
                NtStatus = 0xC0000022, // STATUS_ACCESS_DENIED
                GatingStatus = KernelGatingStatus.BlockedAccessDenied
            };

            bool replied = await ipc.SendReplyAsync(reply);
            Assert.True(replied);
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
    }
}
