using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
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
    /// <summary>
    /// Golden Regression Test Suite for Ultron Defender Total Security (AegisPC).
    /// Enforces the core, invariant behaviors of the antivirus engine that must NEVER regress:
    /// 1. EICAR Detection (standard path &amp; whitelisted developer directory).
    /// 2. Zero Self-Detection (.pdb, .db, and own installation paths).
    /// 3. Zero False Positives on benign user files (.txt, .pdf, .jpg).
    /// 4. Quarantine and Restore roundtrip cryptographic integrity.
    /// 5. Risk Scoring Engine threshold band calibrations.
    /// </summary>
    [Collection("SequentialDiskTests")]
    public class GoldenTestSuite : IDisposable
    {
        private readonly string _sandboxDir;
        private readonly string _vaultDir;
        private readonly IHashService _hashService;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IRiskScoringEngine _riskScoringEngine;
        private readonly IAllowlistService _allowlistService;
        private readonly ISecurityFindingService _findingService;
        private readonly IQuarantineService _quarantineService;
        private readonly IFileScanner _fileScanner;
        private readonly RealTimeProtectionEngine _realTimeEngine;

        private const string EicarStandardPayload = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        /// <summary>
        /// Initializes the test environment, sandbox directories, and engine dependencies.
        /// </summary>
        public GoldenTestSuite()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "AegisPC_GoldenTest_" + Guid.NewGuid().ToString("N"));
            _vaultDir = Path.Combine(_sandboxDir, "Vault");

            Directory.CreateDirectory(_sandboxDir);
            Directory.CreateDirectory(_vaultDir);

            _hashService = new HashService();
            _signatureVerifier = new SignatureVerifier();
            _riskScoringEngine = new RiskScoringEngine();
            _findingService = new SecurityFindingService();
            _allowlistService = new AllowlistService(_hashService);
            _quarantineService = new QuarantineService(_hashService, customVaultDir: _vaultDir);
            _fileScanner = new FileScannerService(_hashService, _signatureVerifier, _riskScoringEngine, _allowlistService, _findingService);

            _realTimeEngine = new RealTimeProtectionEngine(
                _fileScanner,
                _hashService,
                _signatureVerifier,
                _riskScoringEngine,
                _quarantineService,
                _findingService);
        }

        /// <summary>
        /// Cleans up sandbox files and quarantine vault directories upon test completion.
        /// </summary>
        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, recursive: true);
                }
            }
            catch
            {
                // Best-effort cleanup of temporary test sandbox
            }
        }

        #region 1. EICAR Detection Invariants
        /// <summary>
        /// Invariant 1: Verifies that EICAR test samples are detected as ConfirmedMalicious,
        /// both in a regular folder (Downloads) and inside a developer library directory (node_modules).
        /// Whitelisted directories must NOT create a blind spot for real-time protection.
        /// </summary>
        [Fact]
        public async Task Golden01_EicarDetection_InDownloadsAndNodeModules_BothDetectedAsConfirmedMalicious()
        {
            // 1. Standard Downloads directory
            var downloadsDir = Path.Combine(_sandboxDir, "Downloads");
            Directory.CreateDirectory(downloadsDir);
            var standardEicarPath = Path.Combine(downloadsDir, "eicar_standard.com");
            await File.WriteAllTextAsync(standardEicarPath, EicarStandardPayload);

            // 2. Whitelisted Developer directory (node_modules)
            var nodeModulesDir = Path.Combine(_sandboxDir, "my_project", "node_modules", "vendor_pkg");
            Directory.CreateDirectory(nodeModulesDir);
            var hiddenEicarPath = Path.Combine(nodeModulesDir, "package_payload.exe");
            await File.WriteAllTextAsync(hiddenEicarPath, EicarStandardPayload);

            // Evaluate standard EICAR
            var verdictStandard = await _realTimeEngine.InspectFileAsync(standardEicarPath);
            Assert.Equal(RealTimeVerdict.ConfirmedMalicious, verdictStandard.Verdict);
            Assert.Equal(100, verdictStandard.RiskScore);
            Assert.Equal(RealTimePolicyAction.BlockAndQuarantine, verdictStandard.RecommendedPolicy);
            Assert.Contains("EICAR", verdictStandard.ThreatTitle);

            // Evaluate EICAR inside node_modules
            var verdictHidden = await _realTimeEngine.InspectFileAsync(hiddenEicarPath);
            Assert.Equal(RealTimeVerdict.ConfirmedMalicious, verdictHidden.Verdict);
            Assert.Equal(100, verdictHidden.RiskScore);
            Assert.Equal(RealTimePolicyAction.BlockAndQuarantine, verdictHidden.RecommendedPolicy);
        }
        #endregion

        #region 2. Zero Self-Detection Invariants
        /// <summary>
        /// Invariant 2: Verifies that the application's own files (.pdb, .db, .runtimeconfig.json, .exe)
        /// and its base directory are NEVER flagged as threats or quarantined.
        /// </summary>
        [Fact]
        public async Task Golden02_ZeroSelfDetection_AppFilesAndBaseDirectory_AlwaysCleanAndAllowed()
        {
            string appBaseDir = AppDomain.CurrentDomain.BaseDirectory;
            string selfPdb = Path.Combine(appBaseDir, "AegisPC.Security.pdb");
            string selfConfig = Path.Combine(appBaseDir, "UltronDefender.runtimeconfig.json");
            string selfExe = Path.Combine(appBaseDir, "UltronDefender.exe");

            // Self-owned path predicate check
            Assert.True(FileScannerService.IsSelfOwnedPath(selfPdb));
            Assert.True(FileScannerService.IsSelfOwnedPath(selfConfig));
            Assert.True(FileScannerService.IsSelfOwnedPath(selfExe));

            // Real-Time Engine inspection must always evaluate as Clean and Allow
            var verdictPdb = await _realTimeEngine.InspectFileAsync(selfPdb);
            Assert.Equal(RealTimeVerdict.Clean, verdictPdb.Verdict);
            Assert.Equal(0, verdictPdb.RiskScore);
            Assert.Equal(RealTimePolicyAction.Allow, verdictPdb.RecommendedPolicy);

            var verdictConfig = await _realTimeEngine.InspectFileAsync(selfConfig);
            Assert.Equal(RealTimeVerdict.Clean, verdictConfig.Verdict);
            Assert.Equal(0, verdictConfig.RiskScore);
            Assert.Equal(RealTimePolicyAction.Allow, verdictConfig.RecommendedPolicy);

            // File scanner inspection should skip or return clean
            var scanFinding = await _fileScanner.ScanFileAsync(selfPdb);
            Assert.Null(scanFinding);
        }
        #endregion

        #region 3. Zero False Positives on Benign Files
        /// <summary>
        /// Invariant 3: Verifies that legitimate, benign user files (.txt, .pdf, .jpg)
        /// never produce malicious or suspicious verdicts (Score &lt; 40, Verdict Clean, Action Allow).
        /// </summary>
        [Fact]
        public async Task Golden03_ZeroFalsePositives_BenignUserFiles_ProduceCleanAndAllowedVerdict()
        {
            var txtFile = Path.Combine(_sandboxDir, "contract_agreement.txt");
            var pdfFile = Path.Combine(_sandboxDir, "quarterly_report.pdf");
            var jpgFile = Path.Combine(_sandboxDir, "company_logo.jpg");

            // Legitimate text document
            await File.WriteAllTextAsync(txtFile, "Sayin Musteri, Gizlilik ve Hizmet Sozlesmesi ektedir. Tarih: 2026.");

            // Valid PDF header and ASCII content
            await File.WriteAllBytesAsync(pdfFile, Encoding.UTF8.GetBytes("%PDF-1.4 harmless annual budget report contents"));

            // Valid JPEG JFIF header
            var dummyJpg = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00 };
            await File.WriteAllBytesAsync(jpgFile, dummyJpg);

            var verdictTxt = await _realTimeEngine.InspectFileAsync(txtFile);
            Assert.Equal(RealTimeVerdict.Clean, verdictTxt.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, verdictTxt.RecommendedPolicy);
            Assert.True(verdictTxt.RiskScore < 40);

            var verdictPdf = await _realTimeEngine.InspectFileAsync(pdfFile);
            Assert.Equal(RealTimeVerdict.Clean, verdictPdf.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, verdictPdf.RecommendedPolicy);
            Assert.True(verdictPdf.RiskScore < 40);

            var verdictJpg = await _realTimeEngine.InspectFileAsync(jpgFile);
            Assert.Equal(RealTimeVerdict.Clean, verdictJpg.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, verdictJpg.RecommendedPolicy);
            Assert.True(verdictJpg.RiskScore < 40);
        }
        #endregion

        #region 4. Quarantine and Restore Roundtrip Integrity
        /// <summary>
        /// Invariant 4: Verifies the full quarantine lifecycle:
        /// - Target file is safely encrypted into the vault.
        /// - Original file is removed from disk.
        /// - Vault file on disk is encrypted (no plaintext leakage).
        /// - Restoring the file recovers the exact original bytes and SHA-256 checksum.
        /// </summary>
        [Fact]
        public async Task Golden04_QuarantineAndRestore_PreservesByteIntegrityAndEnforcesEncryption()
        {
            var originalFilePath = Path.Combine(_sandboxDir, "suspicious_test_payload.bin");
            var restoredFilePath = Path.Combine(_sandboxDir, "restored_payload.bin");

            var originalData = Encoding.UTF8.GetBytes("CRITICAL_GOLDEN_SUITE_PAYLOAD_TEST_DATA_" + Guid.NewGuid().ToString("N"));
            var originalSha256 = Convert.ToHexString(SHA256.HashData(originalData)).ToLowerInvariant();
            await File.WriteAllBytesAsync(originalFilePath, originalData);

            // 1. Quarantine file
            bool quarantined = await _quarantineService.QuarantineFileAsync(originalFilePath, "Golden.Test.Threat");
            Assert.True(quarantined, "File should be quarantined successfully.");
            Assert.False(File.Exists(originalFilePath), "Original file must be removed from disk upon quarantine.");

            var items = await _quarantineService.GetQuarantinedItemsAsync();
            Assert.NotEmpty(items);
            var entry = items[0];

            // 2. Verify vault encryption on disk
            Assert.True(File.Exists(entry.QuarantinePath), "Encrypted vault container must exist on disk.");
            var rawVaultBytes = await File.ReadAllBytesAsync(entry.QuarantinePath);
            Assert.DoesNotContain(Encoding.UTF8.GetString(originalData), Encoding.ASCII.GetString(rawVaultBytes));

            // 3. Restore file
            bool restored = await _quarantineService.RestoreFileAsync(entry.Id, restoredFilePath);
            Assert.True(restored, "File should be restored successfully.");
            Assert.True(File.Exists(restoredFilePath), "Restored file must exist at specified destination.");

            var restoredData = await File.ReadAllBytesAsync(restoredFilePath);
            var restoredSha256 = Convert.ToHexString(SHA256.HashData(restoredData)).ToLowerInvariant();

            Assert.Equal(originalData.Length, restoredData.Length);
            Assert.Equal(originalSha256, restoredSha256);
            Assert.Equal(originalData, restoredData);
        }
        #endregion

        #region 5. Risk Scoring Engine Threshold Band Calibrations
        /// <summary>
        /// Invariant 5: Verifies calibrated risk scoring thresholds:
        /// - 0 - 39: Clean / Low Risk
        /// - 40 - 69: Suspicious / Medium Risk (Warn, never auto-delete)
        /// - 70 - 84: High Risk (PUP / High Risk)
        /// - 85 - 100: Confirmed Malicious (Critical / Block &amp; Quarantine)
        /// </summary>
        [Fact]
        public async Task Golden05_RiskScoringEngine_ThresholdBands_BehaveStrictlyAccordingToPolicy()
        {
            // Case A: Clean Microsoft signed binary in System path -> Score 0, Level Clean
            var cleanAnalysis = new FileAnalysisResult
            {
                FilePath = @"C:\Windows\System32\notepad.exe",
                FileName = "notepad.exe",
                IsSigned = true,
                SignatureValid = true,
                SignaturePublisher = "Microsoft Corporation",
                IsExecutable = true,
                Entropy = 6.0,
                IsKnownLocation = true
            };
            var (cleanScore, cleanLevel, _) = await _riskScoringEngine.CalculateRiskScoreAsync(cleanAnalysis);
            Assert.InRange(cleanScore, 0, 39);
            Assert.Equal(RiskLevel.Clean, cleanLevel);

            // Case B: Suspicious unsigned executable in Temp directory with high entropy -> Score 50-69, Level Suspicious
            var suspiciousAnalysis = new FileAnalysisResult
            {
                FilePath = @"C:\Users\User\AppData\Local\Temp\unverified_tool.exe",
                FileName = "unverified_tool.exe",
                IsSigned = false,
                IsExecutable = true,
                Entropy = 7.6,
                IsKnownLocation = false
            };
            var (suspiciousScore, suspiciousLevel, _) = await _riskScoringEngine.CalculateRiskScoreAsync(suspiciousAnalysis);
            Assert.InRange(suspiciousScore, 50, 69);
            Assert.Equal(RiskLevel.Suspicious, suspiciousLevel);

            // Case C: PUP / High Risk tool pattern in user path with elevated entropy -> Score 70-84, Level HighRisk
            var highRiskAnalysis = new FileAnalysisResult
            {
                FilePath = @"C:\Users\User\Documents\kmsauto_net.exe",
                FileName = "kmsauto_net.exe",
                IsSigned = false,
                IsExecutable = true,
                Entropy = 7.6,
                IsKnownLocation = false
            };
            var (highRiskScore, highRiskLevel, _) = await _riskScoringEngine.CalculateRiskScoreAsync(highRiskAnalysis);
            Assert.InRange(highRiskScore, 70, 84);
            Assert.Equal(RiskLevel.HighRisk, highRiskLevel);

            // Case D: Confirmed Malicious via Known Threat Hash
            var eicarMatch = MalwareSignatureDatabase.CheckHash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
            Assert.True(eicarMatch.IsMatched);
            Assert.InRange(eicarMatch.SeverityScore, 85, 100);
            Assert.Equal(100, eicarMatch.SeverityScore);
        }
        #endregion
    }
}
