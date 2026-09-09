using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class EtwPreExecProtectionTests : IDisposable
    {
        private readonly string _testDir;
        private readonly IDetectionHub _detectionHub;
        private readonly IRiskScoringEngine _riskScoringEngine;
        private readonly ISignatureVerifier _signatureVerifier;

        public EtwPreExecProtectionTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "Ultron_PreExecTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);

            _signatureVerifier = new SignatureVerifier();
            _riskScoringEngine = new RiskScoringEngine();
            _detectionHub = DetectionHubFactory.CreateDefault(
                signatureVerifier: _signatureVerifier);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testDir))
                {
                    Directory.Delete(_testDir, true);
                }
            }
            catch { }
        }

        [Theory]
        [InlineData("svchost.exe")]
        [InlineData("lsass.exe")]
        [InlineData("csrss.exe")]
        [InlineData("explorer.exe")]
        [InlineData("services.exe")]
        public async Task Test_EtwPreExec_CriticalSystemProcesses_AreNeverSuspendedOrBlocked(string procName)
        {
            // Arrange
            var service = new EtwPreExecProtectionService(
                _detectionHub,
                _riskScoringEngine,
                _signatureVerifier);

            string dummyPath = Path.Combine(_testDir, procName);

            // Act: Evaluate with a mock PID (e.g. 1234)
            var decision = await service.EvaluateProcessAsync(1234, dummyPath);

            // Assert: System process must be fast-path whitelisted without suspension
            Assert.True(decision.Whitelisted, $"Critical process '{procName}' must be whitelisted.");
            Assert.False(decision.WasSuspended, $"Critical process '{procName}' must never be suspended.");
            Assert.False(decision.WasBlocked, $"Critical process '{procName}' must never be blocked.");
            Assert.Contains("Critical system process", decision.Reason);
        }

        [Fact]
        public async Task Test_EtwPreExec_SelfOwnedBinary_IsFastPathWhitelisted()
        {
            // Arrange
            var service = new EtwPreExecProtectionService(
                _detectionHub,
                _riskScoringEngine,
                _signatureVerifier);

            string selfPath = typeof(EtwPreExecProtectionService).Assembly.Location;

            // Act
            var decision = await service.EvaluateProcessAsync(Environment.ProcessId, selfPath);

            // Assert
            Assert.True(decision.Whitelisted);
            Assert.False(decision.WasBlocked);
            Assert.False(decision.WasSuspended);
        }

        [Fact]
        public async Task Test_EtwPreExec_SystemPid_IsBypassed()
        {
            // Arrange
            var service = new EtwPreExecProtectionService(
                _detectionHub,
                _riskScoringEngine,
                _signatureVerifier);

            // Act: PID 4 (System)
            var decision = await service.EvaluateProcessAsync(4, @"C:\Windows\System32\ntoskrnl.exe");

            // Assert
            Assert.True(decision.Whitelisted);
            Assert.False(decision.WasSuspended);
            Assert.False(decision.WasBlocked);
        }

        [Fact]
        public async Task Test_EtwPreExec_SignedMicrosoftBinary_IsWhitelisted()
        {
            // Arrange
            var service = new EtwPreExecProtectionService(
                _detectionHub,
                _riskScoringEngine,
                _signatureVerifier);

            string notepadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
            if (!File.Exists(notepadPath))
            {
                notepadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "notepad.exe");
            }

            if (File.Exists(notepadPath))
            {
                // Act
                var decision = await service.EvaluateProcessAsync(99999, notepadPath);

                // Assert
                Assert.True(decision.Whitelisted);
                Assert.False(decision.WasBlocked);
                Assert.Contains("Microsoft", decision.Reason);
            }
        }

        [Fact]
        public async Task Test_EtwPreExec_CleanFile_PermitsExecution()
        {
            // Arrange
            var service = new EtwPreExecProtectionService(
                _detectionHub,
                _riskScoringEngine,
                _signatureVerifier);
            service.ScanTimeout = TimeSpan.FromSeconds(5);

            string cleanFilePath = Path.Combine(_testDir, "benign_tool.exe");
            await File.WriteAllTextAsync(cleanFilePath, "Normal safe utility content without threat signatures.");

            // Act
            var decision = await service.EvaluateProcessAsync(88888, cleanFilePath);

            // Assert
            Assert.False(decision.WasBlocked);
            Assert.True(decision.RiskScore < 70);
            Assert.Equal("Clean execution permitted", decision.Reason);
        }

        [Fact]
        public async Task Test_EtwPreExec_MaliciousEicarBinary_IsBlockedAndAlertTriggered()
        {
            // Arrange
            PreExecThreatAlert? raisedAlert = null;
            var service = new EtwPreExecProtectionService(
                _detectionHub,
                _riskScoringEngine,
                _signatureVerifier)
            {
                ScanTimeout = TimeSpan.FromSeconds(5)
            };

            service.OnThreatBlocked += alert => raisedAlert = alert;

            string eicarPath = Path.Combine(_testDir, "eicar_test.com");
            // Standard EICAR payload string
            await File.WriteAllTextAsync(eicarPath, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            // Act
            var decision = await service.EvaluateProcessAsync(77777, eicarPath);

            // Assert: Must be detected as malicious and blocked
            Assert.True(decision.WasBlocked, "EICAR payload must be blocked pre-execution.");
            Assert.True(decision.RiskScore >= 70, $"Risk score must be >= 70 (Actual: {decision.RiskScore}).");
            Assert.NotNull(raisedAlert);
            Assert.Equal(77777, raisedAlert.ProcessId);
            Assert.Equal(eicarPath, raisedAlert.ImagePath);
        }

        [Fact]
        public async Task Test_EtwPreExec_TimeoutExceeded_ResumesProcessAndLogsWarning()
        {
            // Arrange: DetectionHub with a detector that delays 500ms while timeout is 150ms
            var slowDetector = new SlowMockDetector(TimeSpan.FromMilliseconds(500));
            var customHub = new DetectionHub(new[] { slowDetector });

            var service = new EtwPreExecProtectionService(
                customHub,
                _riskScoringEngine,
                _signatureVerifier);
            service.ScanTimeout = TimeSpan.FromMilliseconds(150);

            string testPath = Path.Combine(_testDir, "slow_target.exe");
            await File.WriteAllTextAsync(testPath, "Dummy binary content");

            // Act
            var sw = Stopwatch.StartNew();
            var decision = await service.EvaluateProcessAsync(66666, testPath);
            sw.Stop();

            // Assert: Must timeout at ~150ms and NOT hang indefinitely
            Assert.True(decision.TimedOut, "Execution must timeout when scan exceeds timeout.");
            Assert.False(decision.WasBlocked, "Timed out process must be released rather than blocked.");
            Assert.Contains("timeout exceeded", decision.Reason);
            Assert.True(sw.ElapsedMilliseconds < 2000, $"Operation should finish close to timeout (Actual: {sw.ElapsedMilliseconds}ms).");
        }

        [Fact]
        public void Test_EtwPreExec_GracefulLifecycle_StartAndStop_DoesNotThrow()
        {
            // Arrange
            var service = new EtwPreExecProtectionService(
                _detectionHub,
                _riskScoringEngine,
                _signatureVerifier);

            // Act & Assert
            var ex = Record.Exception(() =>
            {
                service.Start();
                Assert.True(service.IsRunning);
                service.Stop();
                Assert.False(service.IsRunning);
            });

            Assert.Null(ex);
        }

        private class SlowMockDetector : IDetectorPlugin
        {
            private readonly TimeSpan _delay;
            public string DetectorId => "SlowMock";
            public string DisplayName => "Slow Mock Detector";
            public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticSignature;
            public int Priority => 1;
            public bool IsEnabled { get; set; } = true;

            public SlowMockDetector(TimeSpan delay) => _delay = delay;

            public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
            {
                await Task.Delay(_delay, cancellationToken);
                return Array.Empty<SecurityEvidence>();
            }
        }
    }
}
