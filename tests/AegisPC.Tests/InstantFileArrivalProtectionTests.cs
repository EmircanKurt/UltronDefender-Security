using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class InstantFileArrivalProtectionTests : IDisposable
    {
        private readonly string _testSandboxDir;
        private readonly string _vaultDir;
        private readonly IHashService _hashService;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IRiskScoringEngine _riskScoringEngine;
        private readonly IAllowlistService _allowlistService;
        private readonly IQuarantineService _quarantineService;
        private readonly ISecurityFindingService _findingService;
        private readonly IFileScanner _fileScanner;
        private readonly RealTimeProtectionEngine _engine;

        public InstantFileArrivalProtectionTests()
        {
            _testSandboxDir = Path.Combine(Path.GetTempPath(), "InstantArrivalTests_" + Guid.NewGuid().ToString("N"));
            _vaultDir = Path.Combine(_testSandboxDir, "Vault");
            Directory.CreateDirectory(_testSandboxDir);
            Directory.CreateDirectory(_vaultDir);

            _hashService = new HashService();
            _signatureVerifier = new SignatureVerifier();
            _riskScoringEngine = new RiskScoringEngine();
            _findingService = new SecurityFindingService();
            _allowlistService = new AllowlistService(_hashService);
            _quarantineService = new QuarantineService(_hashService, null, null, _vaultDir);
            _fileScanner = new FileScannerService(_hashService, _signatureVerifier, _riskScoringEngine, _allowlistService, _findingService);

            _engine = new RealTimeProtectionEngine(
                _fileScanner,
                _hashService,
                _signatureVerifier,
                _riskScoringEngine,
                _quarantineService,
                _findingService);
        }

        [Fact]
        public async Task Test1_EicarTestArtifact_InstantDetection_QuarantineAndTelemetry()
        {
            // 1. Arrange: Create EICAR test artifact in sandbox (simulating new download arrival)
            var testFilePath = Path.Combine(_testSandboxDir, "downloaded_test_eicar.exe");
            var eicarString = "PAYLOAD: AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182";
            await File.WriteAllTextAsync(testFilePath, eicarString);

            // Verify before state: File exists on disk
            Assert.True(File.Exists(testFilePath), "Test file MUST exist before instant arrival protection inspection.");

            // 2. Act: Instant Download Inspection
            var verdict = await _engine.InspectFileAsync(testFilePath);

            // 3. Assert Verdict & Policy
            Assert.Equal(RealTimeVerdict.ConfirmedMalicious, verdict.Verdict);
            Assert.Equal(RealTimePolicyAction.BlockAndQuarantine, verdict.RecommendedPolicy);
            Assert.True(verdict.RiskScore >= 90);
            Assert.True(verdict.Confidence >= 0.90);

            // 4. Assert Timing Telemetry (Time-to-Detect & Time-to-Action)
            Assert.True(verdict.TimeToDetectMs > 0, "Time-to-Detect must be measured and positive.");
            Assert.True(verdict.ScanEndTime >= verdict.ScanStartTime);

            // 5. Act: Execute Quarantine Action
            bool quarantined = await _quarantineService.QuarantineFileAsync(testFilePath, verdict.ThreatTitle);
            Assert.True(quarantined, "File quarantine must succeed.");

            // Verify after state: Original file removed from disk, stored securely in vault
            Assert.False(File.Exists(testFilePath), "Original file MUST be removed from arrival folder after quarantine.");
            var items = await _quarantineService.GetQuarantinedItemsAsync();
            Assert.True(items.Count > 0, "Quarantine vault must contain the locked threat artifact.");
        }

        [Fact]
        public async Task Test2_BenignExecutable_InstantArrival_AllowedWithoutInterference()
        {
            var testFilePath = Path.Combine(_testSandboxDir, "benign_helper.exe");
            var dummyPayload = Encoding.ASCII.GetBytes("MZ_SIMULATED_BENIGN_APPLICATION_CODE");
            await File.WriteAllBytesAsync(testFilePath, dummyPayload);

            var verdict = await _engine.InspectFileAsync(testFilePath);

            Assert.Equal(RealTimeVerdict.Clean, verdict.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, verdict.RecommendedPolicy);
            Assert.True(verdict.RiskScore < 40);
            Assert.True(File.Exists(testFilePath), "Benign file MUST remain untouched on disk.");
        }

        [Fact]
        public async Task Test3_SuspiciousFile_WarnPolicy_NeverDeletesUnknownFile()
        {
            // Unsigned executable in Temp with high entropy (simulating suspicious low-confidence arrival)
            var testFilePath = Path.Combine(_testSandboxDir, "suspicious_script.bat");
            var suspiciousContent = "@echo off\n powershell -NoProfile -ExecutionPolicy Bypass -Command \"Write-Host 'Test'\"";
            await File.WriteAllTextAsync(testFilePath, suspiciousContent);

            var verdict = await _engine.InspectFileAsync(testFilePath);

            // Rule: Suspicious / Unknown files MUST NEVER be deleted!
            Assert.True(File.Exists(testFilePath), "CRITICAL: Suspicious/Unknown files must NEVER be deleted automatically without policy.");
            Assert.NotEqual(RealTimePolicyAction.BlockAndQuarantine, verdict.RecommendedPolicy == RealTimePolicyAction.BlockAndQuarantine ? RealTimePolicyAction.BlockAndQuarantine : RealTimePolicyAction.Allow);
        }

        [Fact]
        public async Task Test4_ControlledKeyloggerBehavior_InstantDetectionAndBlock()
        {
            var testFilePath = Path.Combine(_testSandboxDir, "keyboard_hook_driver.dll");
            var keyloggerCode = "EXPORT_HOOK: SetWindowsHookEx(WH_KEYBOARD_LL, HookProc, hInst, 0); GetAsyncKeyState(VK_SHIFT);";
            await File.WriteAllTextAsync(testFilePath, keyloggerCode);

            var verdict = await _engine.InspectFileAsync(testFilePath);

            Assert.Equal(RealTimeVerdict.ConfirmedMalicious, verdict.Verdict);
            Assert.Equal(RealTimePolicyAction.BlockAndQuarantine, verdict.RecommendedPolicy);
            Assert.Contains(verdict.Evidences, e => e.Contains("API") || e.Contains("Klavye") || e.Contains("Hook") || e.Contains("Keylogger"));
            Assert.True(verdict.RiskScore >= 90);
        }

        public void Dispose()
        {
            _engine.Dispose();
            try
            {
                if (Directory.Exists(_testSandboxDir))
                {
                    Directory.Delete(_testSandboxDir, recursive: true);
                }
            }
            catch { }
        }
    }
}
