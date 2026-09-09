using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Kernel;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
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
            Assert.Equal(KernelDriverStatus.SimulatedMode, ipc.DriverStatus);

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
        public async Task Test_KernelIpcService_ProductionPort_ReportsNotInstalled_WhenDriverMissing()
        {
            using var ipc = new KernelIpcService();
            bool connected = await ipc.ConnectAsync("\\AegisFltPort");

            // Driver (.sys) is not compiled or loaded in test environment; must truthfully report NotInstalled
            Assert.False(connected);
            Assert.False(ipc.IsConnected);
            Assert.Equal(KernelDriverStatus.NotInstalled, ipc.DriverStatus);
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
            Assert.False(decision.ShouldQuarantine);
        }

        [Theory]
        [InlineData(20, false, 0x00000000u, KernelGatingStatus.Allowed, false)]               // Tier 1: Clean (<40)
        [InlineData(55, false, 0x00000000u, KernelGatingStatus.Allowed, false)]               // Tier 2: Suspicious (40-69)
        [InlineData(78, true, 0xC0000022u, KernelGatingStatus.BlockedAccessDenied, false)]    // Tier 3: HighRisk (70-84)
        [InlineData(95, true, 0xC0000022u, KernelGatingStatus.BlockedAccessDenied, true)]     // Tier 4: Critical (>=85)
        public async Task Test_KernelGatingEngine_FourTierDecisionMatrix_AllTiersEvaluatedCorrectly(
            int score, bool expectedBlocked, uint expectedNtStatus, KernelGatingStatus expectedStatus, bool expectedQuarantine)
        {
            var hub = new TestDetectionHub(score, $"TierTestThreat_Score_{score}");
            var gatingEngine = new KernelGatingEngine(detectionHub: hub);

            var sampleFile = Path.Combine(_sandboxDir, $"sample_{score}.dat");
            await File.WriteAllTextAsync(sampleFile, "sample binary data");

            var request = new KernelIpcMessage
            {
                MessageId = (ulong)(6000 + score),
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 2000,
                FilePath = sampleFile,
                TimeoutMs = 500
            };

            var decision = await gatingEngine.EvaluatePreOpDecisionAsync(request);

            Assert.Equal(expectedBlocked, decision.IsBlocked);
            Assert.Equal(expectedNtStatus, decision.NtStatus);
            Assert.Equal(expectedStatus, decision.Status);
            Assert.Equal(expectedQuarantine, decision.ShouldQuarantine);
            Assert.Equal(score, decision.RiskScore);
        }

        [Fact]
        public async Task Test_KernelGatingEngine_TrustedSoftwarePolicy_FastPathBypass()
        {
            var testVerifier = new TestSignatureVerifier("Microsoft Windows Operating System", true);
            var gatingEngine = new KernelGatingEngine(signatureVerifier: testVerifier);

            var legitFile = Path.Combine(_sandboxDir, "signed_app.exe");
            await File.WriteAllTextAsync(legitFile, "MZ-mock-legit-app");

            var request = new KernelIpcMessage
            {
                MessageId = 7001,
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 1234,
                FilePath = legitFile,
                TimeoutMs = 500
            };

            var decision = await gatingEngine.EvaluatePreOpDecisionAsync(request);

            Assert.False(decision.IsBlocked);
            Assert.Equal(0x00000000u, decision.NtStatus);
            Assert.Equal(KernelGatingStatus.BypassedTrustedProcess, decision.Status);
            Assert.False(decision.ShouldQuarantine);
        }

        [Fact]
        public async Task Test_KernelGatingEngine_CanaryAndSelfProtection_FastPathBypass()
        {
            var gatingEngine = new KernelGatingEngine();

            var canaryFile = Path.Combine(_sandboxDir, "!_ultron_shield_canary.docx");
            await File.WriteAllTextAsync(canaryFile, "Canary bait content");

            var requestCanary = new KernelIpcMessage
            {
                MessageId = 7002,
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 1234,
                FilePath = canaryFile,
                TimeoutMs = 500
            };

            var decisionCanary = await gatingEngine.EvaluatePreOpDecisionAsync(requestCanary);
            Assert.False(decisionCanary.IsBlocked);
            Assert.Equal(0x00000000u, decisionCanary.NtStatus);
            Assert.Equal(KernelGatingStatus.Allowed, decisionCanary.Status);
            Assert.False(decisionCanary.ShouldQuarantine);

            var requestSelf = new KernelIpcMessage
            {
                MessageId = 7003,
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 1234,
                FilePath = @"C:\Program Files\UltronDefender\UltronDefender.exe",
                TimeoutMs = 500
            };

            var decisionSelf = await gatingEngine.EvaluatePreOpDecisionAsync(requestSelf);
            Assert.False(decisionSelf.IsBlocked);
            Assert.Equal(0x00000000u, decisionSelf.NtStatus);
            Assert.Equal(KernelGatingStatus.Allowed, decisionSelf.Status);
        }

        [Fact]
        public async Task Test_KernelGatingEngine_FailOpenTimeoutSafety_UnderCancellation()
        {
            var gatingEngine = new KernelGatingEngine();
            var targetFile = Path.Combine(_sandboxDir, "timeout_test.bin");
            await File.WriteAllTextAsync(targetFile, "content for timeout test");

            using var cts = new CancellationTokenSource();
            cts.Cancel(); // Pre-cancel token to simulate immediate timeout

            var request = new KernelIpcMessage
            {
                MessageId = 7004,
                OpCode = MinifilterOperationType.PreCreate,
                ProcessId = 1234,
                FilePath = targetFile,
                TimeoutMs = 1
            };

            var decision = await gatingEngine.EvaluatePreOpDecisionAsync(request, cts.Token);

            Assert.False(decision.IsBlocked);
            Assert.Equal(0x00000000u, decision.NtStatus);
            Assert.Equal(KernelGatingStatus.TimeoutFallbackAllowed, decision.Status);
            Assert.False(decision.ShouldQuarantine);
        }

        [Fact]
        public async Task Test_KernelIpcService_DualPortName_Compatibility()
        {
            using var ipc = new KernelIpcService();

            // Production ports report NotInstalled when driver is not running
            bool defaultPortResult = await ipc.ConnectAsync(IKernelIpcService.DefaultPortName);
            Assert.False(defaultPortResult);
            Assert.Equal(KernelDriverStatus.NotInstalled, ipc.DriverStatus);

            bool legacyPortResult = await ipc.ConnectAsync(IKernelIpcService.LegacyPortName);
            Assert.False(legacyPortResult);
            Assert.Equal(KernelDriverStatus.NotInstalled, ipc.DriverStatus);

            // Simulation / Test ports enter SimulatedMode
            bool simResultDefault = await ipc.ConnectAsync("\\AegisFilterPort_Test");
            Assert.True(simResultDefault);
            Assert.Equal(KernelDriverStatus.SimulatedMode, ipc.DriverStatus);

            await ipc.DisconnectAsync();

            bool simResultLegacy = await ipc.ConnectAsync("\\AegisFltPort_Simulated");
            Assert.True(simResultLegacy);
            Assert.Equal(KernelDriverStatus.SimulatedMode, ipc.DriverStatus);
        }

        private class TestDetectionHub : IDetectionHub
        {
            private readonly int _score;
            private readonly string _threatTitle;

            public TestDetectionHub(int score, string threatTitle)
            {
                _score = score;
                _threatTitle = threatTitle;
            }

            public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => Array.Empty<IDetectorPlugin>();
            public void RegisterDetector(IDetectorPlugin detector) { }
            public bool UnregisterDetector(string detectorId) => true;

            public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
            {
                return Task.FromResult(new DetectionResult
                {
                    RiskScore = _score,
                    ThreatTitle = _threatTitle,
                    Verdict = _score >= 85 ? DetectionVerdict.ConfirmedMalicious : (_score >= 70 ? DetectionVerdict.Suspicious : DetectionVerdict.Clean)
                });
            }
        }

        private class TestSignatureVerifier : ISignatureVerifier
        {
            private readonly string _publisher;
            private readonly bool _isValid;

            public TestSignatureVerifier(string publisher, bool isValid = true)
            {
                _publisher = publisher;
                _isValid = isValid;
            }

            public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default)
            {
                return Task.FromResult(new SignatureInfo
                {
                    IsSigned = true,
                    IsValid = _isValid,
                    Publisher = _publisher
                });
            }
        }
    }
}
