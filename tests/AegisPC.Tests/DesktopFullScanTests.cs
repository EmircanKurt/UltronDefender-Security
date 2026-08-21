using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class DesktopFullScanTests : IDisposable
    {
        private readonly string _testSandboxDir;
        private readonly FileScannerService _scanner;
        private readonly SecurityFindingService _findingService;
        private readonly HashService _hashService;
        private readonly SignatureVerifier _sigVerifier;
        private readonly RiskScoringEngine _riskEngine;
        private readonly AllowlistService _allowlist;
        private readonly IDetectionHub _detectionHub;

        public DesktopFullScanTests()
        {
            _testSandboxDir = Path.Combine(Path.GetTempPath(), "AegisDesktopScanTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testSandboxDir);

            _hashService = new HashService();
            _sigVerifier = new SignatureVerifier();
            _riskEngine = new RiskScoringEngine();
            _findingService = new SecurityFindingService();
            _allowlist = new AllowlistService(_hashService);
            _detectionHub = DetectionHubFactory.CreateDefault(_hashService, _sigVerifier);

            _scanner = new FileScannerService(
                _hashService,
                _sigVerifier,
                _riskEngine,
                _allowlist,
                _findingService,
                _detectionHub);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testSandboxDir))
                {
                    Directory.Delete(_testSandboxDir, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Test_DesktopSyntheticMalware_DetectedImmediately()
        {
            var desktopDir = Path.Combine(_testSandboxDir, "Desktop");
            Directory.CreateDirectory(desktopDir);

            var samplePath = Path.Combine(desktopDir, "suspicious_payload.exe");
            await File.WriteAllTextAsync(samplePath, "AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182");

            var result = await _scanner.ScanDirectoryAsync(desktopDir, ScanType.Custom);

            Assert.NotNull(result);
            Assert.True(result.Findings.Count >= 1);
            var finding = result.Findings.First();
            Assert.Equal(samplePath, finding.ObjectPath);
            Assert.True(finding.RiskScore >= 85);
            Assert.Equal(RiskLevel.ConfirmedMalicious, finding.RiskLevel);
        }

        [Fact]
        public async Task Test_ContentOverExtension_BinaryDetectedRegardlessOfExtension()
        {
            var desktopDir = Path.Combine(_testSandboxDir, "Desktop");
            Directory.CreateDirectory(desktopDir);

            // File named .dat with synthetic malware signature
            var sampleDat = Path.Combine(desktopDir, "hidden_trojan.dat");
            await File.WriteAllTextAsync(sampleDat, "AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182");

            // File named .tmp with script heuristic payload (encoded in Base64)
            var sampleTmp = Path.Combine(desktopDir, "ransom_script.tmp");
            var scriptPayload = Encoding.UTF8.GetString(Convert.FromBase64String("dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL2FsbCAvcXVpZXQ="));
            await File.WriteAllTextAsync(sampleTmp, scriptPayload);

            var findingDat = await _scanner.ScanFileAsync(sampleDat);
            var findingTmp = await _scanner.ScanFileAsync(sampleTmp);

            Assert.NotNull(findingDat);
            Assert.Equal(sampleDat, findingDat.ObjectPath);

            Assert.NotNull(findingTmp);
            Assert.Equal(sampleTmp, findingTmp.ObjectPath);
        }

        [Fact]
        public async Task Test_ScanDirectory_ResilientToInaccessibleOrNestedDirectories()
        {
            var subDir1 = Path.Combine(_testSandboxDir, "Folder1");
            var subDir2 = Path.Combine(_testSandboxDir, "Folder2", "Nested");
            Directory.CreateDirectory(subDir1);
            Directory.CreateDirectory(subDir2);

            // Clean benign file
            await File.WriteAllTextAsync(Path.Combine(subDir1, "clean_file.txt"), "This is a clean user document.");

            // Threat file in deeply nested folder (encoded in Base64)
            var threatFile = Path.Combine(subDir2, "nested_threat.bat");
            var batPayload = Encoding.UTF8.GetString(Convert.FromBase64String("dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL2FsbCAvcXVpZXQgJiBiY2RlZGl0IC9zZXQge2RlZmF1bHR9IHJlY292ZXJ5ZW5hYmxlZCBObw=="));
            await File.WriteAllTextAsync(threatFile, batPayload);

            var result = await _scanner.ScanDirectoryAsync(_testSandboxDir, ScanType.Custom);

            Assert.NotNull(result);
            Assert.True(result.TotalFiles >= 2);
            Assert.True(result.Findings.Count >= 1);
            Assert.Contains(result.Findings, f => f.ObjectPath == threatFile);
        }
    }
}
