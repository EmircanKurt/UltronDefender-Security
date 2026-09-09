using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class PupScoringTests
    {
        private readonly RiskScoringEngine _engine = new();

        [Fact]
        public async Task CalculateRiskScore_UnsignedCrackExecutable_CategorizedAsHighRiskPUP()
        {
            var analysis = new FileAnalysisResult
            {
                FileName = "photoshop_keygen_v2.exe",
                FilePath = @"C:\Users\PC\Downloads\photoshop_keygen_v2.exe",
                IsExecutable = true,
                IsSigned = false,
                Entropy = 6.2,
                IsKnownLocation = false
            };

            var (score, level, reasons) = await _engine.CalculateRiskScoreAsync(analysis);

            Assert.True(score >= 60);
            Assert.Equal(RiskLevel.HighRisk, level);
            Assert.Contains(reasons, r => r.Contains("PUP/Crack/Keygen"));
        }

        [Fact]
        public async Task CalculateRiskScore_DoubleExtensionDisguise_FlaggedConfirmedMalicious()
        {
            var analysis = new FileAnalysisResult
            {
                FileName = "invoice_2026.pdf.exe",
                FilePath = @"C:\Users\PC\Downloads\invoice_2026.pdf.exe",
                IsExecutable = true,
                IsSigned = false,
                Entropy = 7.1,
                IsKnownLocation = false
            };

            var (score, level, reasons) = await _engine.CalculateRiskScoreAsync(analysis);

            Assert.True(score >= 80);
            Assert.Equal(RiskLevel.ConfirmedMalicious, level);
            Assert.Contains(reasons, r => r.Contains("Çift uzantı"));
        }

        [Fact]
        public async Task CalculateRiskScore_SignedSystemBinary_ReturnsClean()
        {
            var analysis = new FileAnalysisResult
            {
                FileName = "svchost.exe",
                FilePath = @"C:\Windows\System32\svchost.exe",
                IsExecutable = true,
                IsSigned = true,
                SignatureValid = true,
                SignaturePublisher = "Microsoft Windows Publisher",
                Entropy = 6.4,
                IsKnownLocation = true
            };

            var (score, level, _) = await _engine.CalculateRiskScoreAsync(analysis);

            Assert.Equal(0, score);
            Assert.Equal(RiskLevel.Clean, level);
        }

        [Fact]
        public async Task CalculateRiskScore_ExtremeShannonEntropy_AddsHighRiskPenalty()
        {
            var analysis = new FileAnalysisResult
            {
                FileName = "unknown_packed_binary.exe",
                FilePath = @"C:\Users\PC\AppData\Local\Temp\unknown_packed_binary.exe",
                IsExecutable = true,
                IsSigned = false,
                Entropy = 7.92,
                IsKnownLocation = false
            };

            var (score, level, reasons) = await _engine.CalculateRiskScoreAsync(analysis);

            Assert.True(score >= 60);
            Assert.Contains(reasons, r => r.Contains("Shannon entropisi"));
        }

        [Fact]
        public async Task CalculateRiskScore_MalwareInRepackNamedFolder_CannotBypassPupDetection()
        {
            // Verifies P0 #2 fix: Dropping a PUP / unsigned tool into a folder named 'fitgirl'
            // must NOT bypass PUP detection or receive automatic negative score exemptions.
            var analysis = new FileAnalysisResult
            {
                FileName = "miner_payload.exe",
                FilePath = @"C:\Users\PC\Downloads\fitgirl\miner_payload.exe",
                IsExecutable = true,
                IsSigned = false,
                Entropy = 6.8,
                IsKnownLocation = false
            };

            var (score, level, reasons) = await _engine.CalculateRiskScoreAsync(analysis);

            Assert.True(score >= 50, $"Expected risk score >= 50, but got {score}");
            Assert.True(level >= RiskLevel.Suspicious);
            Assert.Contains(reasons, r => r.Contains("PUP/Crack/Keygen"));
            Assert.DoesNotContain(reasons, r => r.Contains("Gamer Protection Shield"));
        }

        [Fact]
        public async Task NegativeMatrix_FilePathCannotAlterSecurityVerdictOrExemptMalware()
        {
            // Section 5 Mandatory Negative Matrix:
            // Verifies that path name NEVER acts as a trust override for malware.
            var testPaths = new[]
            {
                @"C:\Temp\sample.exe",
                @"C:\Games\sample.exe",
                @"C:\Games\SubFolder\sample.exe",
                @"C:\Oyunlar\sample.exe",
                @"C:\Temp\fitgirl\sample.exe",
                @"C:\Temp\dodi\sample.exe",
                @"C:\Temp\codex\sample.exe"
            };

            int? baselineScore = null;
            RiskLevel? baselineLevel = null;

            foreach (var path in testPaths)
            {
                var analysis = new FileAnalysisResult
                {
                    FileName = "sample.exe",
                    FilePath = path,
                    IsExecutable = true,
                    IsSigned = false,
                    Entropy = 6.8,
                    IsKnownLocation = false,
                    SHA256 = "E8B5D34789A5034633215975A0E72C4119B213D5E412A34A9F8BC331D45F8586"
                };

                var (score, level, reasons) = await _engine.CalculateRiskScoreAsync(analysis);

                // No folder discount should ever be awarded
                Assert.DoesNotContain(reasons, r => r.Contains("Gamer Protection Shield"));
                Assert.DoesNotContain(reasons, r => r.Contains("-20"));

                if (baselineScore == null)
                {
                    baselineScore = score;
                    baselineLevel = level;
                }
                else
                {
                    Assert.Equal(baselineScore, score);
                    Assert.Equal(baselineLevel, level);
                }
            }
        }
    }
}
