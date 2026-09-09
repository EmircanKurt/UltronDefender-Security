using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class FalsePositiveReductionTests : IDisposable
    {
        private readonly string _tempDir;

        public FalsePositiveReductionTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), $"UltronFPTest_{Guid.NewGuid():N}");
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempDir))
                {
                    Directory.Delete(_tempDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Test_BenignUnsignedInstaller_EvaluatedAsClean()
        {
            var riskEngine = new RiskScoringEngine();
            string installerPath = Path.Combine(_tempDir, "MyApp_Setup_v1.0.exe");
            await File.WriteAllTextAsync(installerPath, "MZ-simulated-installer-executable");

            var analysis = new FileAnalysisResult
            {
                FilePath = installerPath,
                FileName = Path.GetFileName(installerPath),
                IsExecutable = true,
                IsSigned = false,
                SignatureValid = false,
                IsKnownLocation = false,
                Entropy = 6.2,
                IsPacked = false,
                SHA256 = "1111111111111111111111111111111111111111111111111111111111111111"
            };

            var (score, level, reasons) = await riskEngine.CalculateRiskScoreAsync(analysis);

            // Benign unsigned installer must not exceed the suspicious threshold (40)
            Assert.True(score < 40, $"Expected clean score (<40) for benign installer, but got {score}. Reasons: {string.Join("; ", reasons)}");
            Assert.Equal(RiskLevel.Clean, level);
        }

        [Fact]
        public async Task Test_SignedMicrosoftBinary_EvaluatedAsFullyTrustedClean()
        {
            var riskEngine = new RiskScoringEngine();
            string sysFilePath = @"C:\Windows\System32\notepad.exe";

            var analysis = new FileAnalysisResult
            {
                FilePath = sysFilePath,
                FileName = "notepad.exe",
                IsExecutable = true,
                IsSigned = true,
                SignatureValid = true,
                SignaturePublisher = "Microsoft Windows",
                IsKnownLocation = true,
                Entropy = 6.5,
                IsPacked = false,
                SHA256 = "2222222222222222222222222222222222222222222222222222222222222222"
            };

            var (score, level, reasons) = await riskEngine.CalculateRiskScoreAsync(analysis);

            Assert.Equal(0, score);
            Assert.Equal(RiskLevel.Clean, level);
            Assert.Contains(reasons, r => r.Contains("Microsoft", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task Test_GameModTool_EvaluatedAsCleanWithoutFalseAlert()
        {
            var riskEngine = new RiskScoringEngine();
            // Typical game directory with modding tool
            string gamePath = @"D:\Games\Skyrim\enbseries.dll";

            var analysis = new FileAnalysisResult
            {
                FilePath = gamePath,
                FileName = "enbseries.dll",
                IsExecutable = true,
                IsSigned = false,
                SignatureValid = false,
                IsKnownLocation = false,
                Entropy = 6.8,
                IsPacked = false,
                SHA256 = "3333333333333333333333333333333333333333333333333333333333333333"
            };

            var (score, level, reasons) = await riskEngine.CalculateRiskScoreAsync(analysis);

            Assert.True(score < 40, $"Expected clean score (<40) for game mod tool, got {score}. Reasons: {string.Join("; ", reasons)}");
            Assert.Equal(RiskLevel.Clean, level);
        }

        [Fact]
        public async Task Test_PackedBenignUtility_EvaluatedAsCleanWithoutCorroboratingThreat()
        {
            var riskEngine = new RiskScoringEngine();
            string utilityPath = Path.Combine(_tempDir, "UtilityTool.exe");
            await File.WriteAllTextAsync(utilityPath, "MZ-simulated-upx-utility");

            var analysis = new FileAnalysisResult
            {
                FilePath = utilityPath,
                FileName = "UtilityTool.exe",
                IsExecutable = true,
                IsSigned = false,
                SignatureValid = false,
                IsKnownLocation = false,
                Entropy = 7.1,
                IsPacked = true,
                PackerName = "UPX",
                SHA256 = "4444444444444444444444444444444444444444444444444444444444444444"
            };

            var (score, level, reasons) = await riskEngine.CalculateRiskScoreAsync(analysis);

            // UPX packing alone without any other suspicious signals should stay Clean (<40)
            Assert.True(score < 40, $"Expected clean score (<40) for UPX compressed benign utility, got {score}. Reasons: {string.Join("; ", reasons)}");
            Assert.Equal(RiskLevel.Clean, level);
        }

        [Fact]
        public async Task Test_NormalUserFileInTempOrAppData_DoesNotTriggerFalseAlert()
        {
            var riskEngine = new RiskScoringEngine();
            string appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NormalApp", "Helper.exe");

            var analysis = new FileAnalysisResult
            {
                FilePath = appDataPath,
                FileName = "Helper.exe",
                IsExecutable = true,
                IsSigned = false,
                SignatureValid = false,
                IsKnownLocation = false,
                Entropy = 5.9,
                IsPacked = false,
                SHA256 = "5555555555555555555555555555555555555555555555555555555555555555"
            };

            var (score, level, reasons) = await riskEngine.CalculateRiskScoreAsync(analysis);

            Assert.True(score < 40, $"Expected clean score (<40) for normal file in AppData, got {score}. Reasons: {string.Join("; ", reasons)}");
            Assert.Equal(RiskLevel.Clean, level);
        }

        [Fact]
        public void Test_TrustedSoftwarePolicy_DistinctMethods_IdentifyCategoriesCorrectly()
        {
            // 1. Microsoft Signed System
            bool isMs = TrustedSoftwarePolicy.IsMicrosoftSignedSystem(@"C:\Windows\System32\kernel32.dll", "Microsoft Windows", true, true);
            Assert.True(isMs);

            // 2. Program Files Commercial Signed
            bool isCommercial = TrustedSoftwarePolicy.IsProgramFilesCommercialSigned(
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "Google LLC",
                true,
                true);
            Assert.True(isCommercial);

            // 3. Invalid signature should not be trusted
            bool invalidSig = TrustedSoftwarePolicy.IsProgramFilesCommercialSigned(
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "Google LLC",
                true,
                false);
            Assert.False(invalidSig);
        }
    }
}
