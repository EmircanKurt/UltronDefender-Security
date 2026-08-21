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
    }
}
