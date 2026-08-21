using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class RiskScoringEngineTests
    {
        private readonly RiskScoringEngine _engine = new();

        [Fact]
        public async Task CalculateRiskScoreAsync_SignedTrustedApp_ReturnsLowRisk()
        {
            var analysis = new FileAnalysisResult
            {
                FilePath = @"C:\Program Files\App\test.exe",
                FileName = "test.exe",
                IsSigned = true,
                SignatureValid = true,
                SignaturePublisher = "Microsoft Corporation",
                Entropy = 5.5,
                IsExecutable = true
            };

            var (score, level, reasons) = await _engine.CalculateRiskScoreAsync(analysis);

            Assert.Equal(0, score);
            Assert.Equal(RiskLevel.Clean, level);
        }

        [Fact]
        public async Task CalculateRiskScoreAsync_UnsignedExecutableInTempWithHighEntropy_ReturnsHighRisk()
        {
            var analysis = new FileAnalysisResult
            {
                FilePath = @"C:\Users\User\AppData\Local\Temp\evil.exe",
                FileName = "evil.exe",
                IsSigned = false,
                Entropy = 7.6,
                IsExecutable = true
            };

            var (score, level, reasons) = await _engine.CalculateRiskScoreAsync(analysis);

            Assert.True(score >= 50);
            Assert.True(level >= RiskLevel.Suspicious);
            Assert.NotEmpty(reasons);
        }
    }
}
