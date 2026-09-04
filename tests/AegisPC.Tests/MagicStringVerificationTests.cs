using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    /// <summary>
    /// Kural 7.1 uyarınca dosya adına ("keygen.exe", "crack.exe") bakarak
    /// güvenlik kararı verilmediğini, kararın nesnel hash/imza/entropi/davranışa
    /// dayandığını doğrulayan gerçek dosya testi.
    /// </summary>
    public class MagicStringVerificationTests
    {
        [Fact]
        public async Task KeygenExe_OnDesktop_WithBenignContent_IsNeverPenalizedByName()
        {
            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var testFilePath = Path.Combine(desktopPath, "keygen.exe");

            try
            {
                // 1. Masaüstünde içi zararsız metin/boş olan "keygen.exe" oluştur
                File.WriteAllText(testFilePath, "This is a benign harmless test file named keygen.exe");

                // 2. RiskScoringEngine doğrudan analiz etsin
                var scoringEngine = new RiskScoringEngine();
                var analysis = new FileAnalysisResult
                {
                    FileName = "keygen.exe",
                    FilePath = testFilePath,
                    IsExecutable = false, // Gerçek bir PE değil, düz metin
                    IsSigned = false,
                    Entropy = 2.1, // Çok düşük, şifreli/paketlenmiş değil
                    IsKnownLocation = false,
                    SHA256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
                };

                var (score, level, reasons) = await scoringEngine.CalculateRiskScoreAsync(analysis);

                // DOĞRULAMA: Dosya adında "keygen" geçtiği için ceza puanı ALMAMALI!
                // Eskiden olsa score >= 50 ve PUP uyarısı verirdi.
                Assert.Equal(0, score);
                Assert.Equal(RiskLevel.Clean, level);
                Assert.DoesNotContain(reasons, r => r.Contains("keygen", StringComparison.OrdinalIgnoreCase));

                // 3. FileScannerService ile tara
                var hashService = new HashService();
                var sigVerifier = new SignatureVerifier();
                var findingService = new SecurityFindingService(null);
                var scanner = new FileScannerService(
                    hashService,
                    sigVerifier,
                    scoringEngine,
                    new AllowlistService(hashService),
                    findingService);

                var finding = await scanner.ScanFileAsync(testFilePath);

                // DOĞRULAMA: Dosya temiz bulunmalı, karantinaya alınmamalı
                Assert.Null(finding);
            }
            finally
            {
                // 4. Test dosyasını masaüstünden temizle
                if (File.Exists(testFilePath))
                {
                    try
                    {
                        File.Delete(testFilePath);
                    }
                    catch { }
                }
            }
        }
    }
}
