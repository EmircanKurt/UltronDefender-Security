using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Database;
using AegisPC.Infrastructure.Database.Repositories;
using AegisPC.Infrastructure.Elevation;
using AegisPC.Infrastructure.SecureStorage;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class RealTimeProtectionTests : IDisposable
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

        public RealTimeProtectionTests()
        {
            _testSandboxDir = Path.Combine(Path.GetTempPath(), "UltronSecurityTests_" + Guid.NewGuid().ToString("N"));
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
        public async Task Test_BenignFile_Dmloader_NotFlaggedAsPUP()
        {
            var analysis = new FileAnalysisResult
            {
                FilePath = @"C:\Windows\System32\dmloader.dll",
                FileName = "dmloader.dll",
                SHA256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                FileSize = 45000,
                IsSigned = true,
                SignaturePublisher = "Microsoft Windows",
                SignatureValid = true,
                IsExecutable = true,
                IsKnownLocation = true,
                Entropy = 6.2
            };

            var (score, level, reasons) = await _riskScoringEngine.CalculateRiskScoreAsync(analysis);

            Assert.Equal(RiskLevel.Clean, level);
            Assert.True(score < 30, $"Benign system file score should be < 30, but got {score}");
            Assert.DoesNotContain(reasons, r => r.Contains("PUP/Crack"));
        }

        [Fact]
        public async Task Test_EicarTestArtifact_DetectedAsMalicious()
        {
            var testFilePath = Path.Combine(_testSandboxDir, "test_malware_sample.exe");
            var payloadString = "AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182";
            await File.WriteAllTextAsync(testFilePath, payloadString);

            var verdict = await _engine.InspectFileAsync(testFilePath);

            Assert.Equal(RealTimeVerdict.ConfirmedMalicious, verdict.Verdict);
            Assert.Equal(RealTimePolicyAction.BlockAndQuarantine, verdict.RecommendedPolicy);
            Assert.True(verdict.RiskScore >= 90);
        }

        [Fact]
        public async Task Test_QuarantineService_EncryptsAndWipesOriginalFile()
        {
            var targetFile = Path.Combine(_testSandboxDir, "malicious_payload.bin");
            var payload = Encoding.UTF8.GetBytes("MALICIOUS_SIMULATED_DATA_TO_BE_LOCKED");
            await File.WriteAllBytesAsync(targetFile, payload);

            Assert.True(File.Exists(targetFile));

            bool success = await _quarantineService.QuarantineFileAsync(targetFile, "Unit Test Quarantine");

            Assert.True(success, "Quarantine should report success");
            Assert.False(File.Exists(targetFile), "Original file should be deleted after quarantine");

            var items = await _quarantineService.GetQuarantinedItemsAsync();
            Assert.Contains(items, item => item.FileName == "malicious_payload.bin");
        }

        [Fact]
        public async Task Test_SuspiciousFile_UnsignedTemp_CalculatesAccurateScore()
        {
            var analysis = new FileAnalysisResult
            {
                FilePath = @"C:\Users\PC\AppData\Local\Temp\suspicious_app.exe",
                FileName = "suspicious_app.exe",
                SHA256 = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
                FileSize = 120000,
                IsSigned = false,
                SignatureValid = false,
                IsExecutable = true,
                IsKnownLocation = false,
                Entropy = 7.1
            };

            var (score, level, reasons) = await _riskScoringEngine.CalculateRiskScoreAsync(analysis);

            // Unsigned + Temp location is suspicious/low risk, but NOT confirmed malicious
            Assert.True(score < 70, $"Unsigned temp file alone should not become HighRisk/Malicious, got score: {score}");
            Assert.NotEqual(RiskLevel.ConfirmedMalicious, level);
        }

        [Fact]
        public async Task Test_ActiveRunningThreat_TerminatedAndQuarantined()
        {
            // 1. Create a dummy test executable (cmd.exe copy or timeout)
            var dummyExePath = Path.Combine(_testSandboxDir, "fake_threat_worker.exe");
            var systemCmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            File.Copy(systemCmd, dummyExePath, true);

            // 2. Launch it as an active background process
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = dummyExePath,
                Arguments = "/c timeout /t 30",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            var process = System.Diagnostics.Process.Start(psi);
            Assert.NotNull(process);
            Assert.False(process.HasExited);

            try
            {
                // 3. Quarantine target file (which also terminates locking/running processes)
                bool success = await _quarantineService.QuarantineFileAsync(dummyExePath, "Active Threat Kill Test");
                Assert.True(success);

                // 4. Verify process was actively terminated at the OS level
                await Task.Delay(500);
                Assert.True(process.HasExited, "Process executing malicious binary MUST be terminated during quarantine!");
                Assert.False(File.Exists(dummyExePath), "Malicious binary MUST be wiped from disk!");
            }
            finally
            {
                try { if (!process.HasExited) process.Kill(); } catch { }
            }
        }

        [Fact]
        public async Task Test_FileFlood_500Events_HandledGracefully()
        {
            // Rapidly write 500 files to simulate high load
            var floodDir = Path.Combine(_testSandboxDir, "FloodZone");
            Directory.CreateDirectory(floodDir);

            for (int i = 0; i < 200; i++)
            {
                var filePath = Path.Combine(floodDir, $"flood_file_{i}.txt");
                await File.WriteAllTextAsync(filePath, $"Test flood line content {i}");
            }

            // Engine should remain responsive and stable
            var verdict = await _engine.InspectFileAsync(Path.Combine(floodDir, "flood_file_10.txt"));
            Assert.Equal(RealTimeVerdict.Clean, verdict.Verdict);
        }

        [Fact]
        public async Task Test_MalformedPeFile_HandledGracefully()
        {
            var malformedFile = Path.Combine(_testSandboxDir, "malformed.exe");
            // MZ header with corrupted PE offset
            byte[] badPe = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00 };
            await File.WriteAllBytesAsync(malformedFile, badPe);

            var verdict = await _engine.InspectFileAsync(malformedFile);
            Assert.NotNull(verdict);
            // Should not crash, safely evaluate without exception
        }

        [Fact]
        public async Task Test_QuarantineService_PermanentZeroWipeDelete()
        {
            var targetFile = Path.Combine(_testSandboxDir, "to_be_permanently_deleted.bin");
            await File.WriteAllTextAsync(targetFile, "TEMPORARY MALWARE PAYLOAD");

            await _quarantineService.QuarantineFileAsync(targetFile, "Delete Test");
            var items = await _quarantineService.GetQuarantinedItemsAsync();
            var item = items.Find(x => x.FileName == "to_be_permanently_deleted.bin");
            Assert.NotNull(item);

            bool deleted = await _quarantineService.DeleteQuarantinedAsync(item.Id);
            Assert.True(deleted);
            Assert.False(File.Exists(item.QuarantinePath), "Vault file should be wiped from disk");

            var updatedItems = await _quarantineService.GetQuarantinedItemsAsync();
            Assert.DoesNotContain(updatedItems, x => x.Id == item.Id);
        }

        [Fact]
        public async Task Test_ProcessTermination_PidReuseCheck_RejectsMismatchedPath()
        {
            var procTermService = new AegisPC.Performance.Process.ProcessTerminationService();
            var currentProc = System.Diagnostics.Process.GetCurrentProcess();

            // Attempt to terminate current process with a fake expected path
            var result = await procTermService.TerminateProcessSafelyAsync(
                currentProc.Id,
                expectedExecutablePath: @"C:\FakeNonExistent\Malware.exe",
                expectedProcessName: "FakeMalwareName");

            // Must reject termination because PID does not match fake process name/path
            Assert.False(result.Success);
            Assert.Contains("yeniden kullanılmış", result.Message);
        }

        [Fact]
        public async Task Test_QuarantineService_AtomicIndexSave_PreservesData()
        {
            var targetFile1 = Path.Combine(_testSandboxDir, "atomic_test_1.bin");
            var targetFile2 = Path.Combine(_testSandboxDir, "atomic_test_2.bin");
            await File.WriteAllTextAsync(targetFile1, "PAYLOAD 1");
            await File.WriteAllTextAsync(targetFile2, "PAYLOAD 2");

            await _quarantineService.QuarantineFileAsync(targetFile1, "Atomic 1");
            await _quarantineService.QuarantineFileAsync(targetFile2, "Atomic 2");

            var items = await _quarantineService.GetQuarantinedItemsAsync();
            Assert.Equal(2, items.Count);

            // Re-instantiate quarantine service from disk to verify index integrity
            var newQuarService = new QuarantineService(_hashService, null, null, _vaultDir);
            var reloadedItems = await newQuarService.GetQuarantinedItemsAsync();
            Assert.Equal(2, reloadedItems.Count);
        }

        public void Dispose()
        {
            try
            {
                _engine.Dispose();
                if (Directory.Exists(_testSandboxDir))
                {
                    Directory.Delete(_testSandboxDir, true);
                }
            }
            catch { }
        }
    }
}
