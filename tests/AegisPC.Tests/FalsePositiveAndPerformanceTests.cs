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
    public class FalsePositiveAndPerformanceTests
    {
        private readonly RiskScoringEngine _scoringEngine = new();

        [Fact]
        public async Task BenignUnsignedInstaller_InDownloads_EvaluatesAsClean()
        {
            // Senaryo: Kullanıcının İndirilenler klasörüne indirdiği meşru, imzasız kurulum aracı (örn: my_setup.exe)
            // Entropi normal (6.1) ve hacktool adı taşımıyor.
            var analysis = new FileAnalysisResult
            {
                FileName = "my_setup.exe",
                FilePath = @"C:\Users\User\Downloads\my_setup.exe",
                IsExecutable = true,
                IsSigned = false,
                Entropy = 6.1,
                IsKnownLocation = false
            };

            var (score, level, reasons) = await _scoringEngine.CalculateRiskScoreAsync(analysis);

            // Beklenti: Yanlış pozitif üretilmemeli, RiskLevel.Clean (< 40) olmalı
            Assert.True(score < 40, $"Expected score < 40 for benign unsigned installer, but got {score}");
            Assert.Equal(RiskLevel.Clean, level);
            Assert.DoesNotContain(reasons, r => r.Contains("PUP/Crack/Keygen"));
        }

        [Fact]
        public async Task BenignApp_InDesktop_WithNormalEntropy_EvaluatesAsClean()
        {
            // Senaryo: Kullanıcının Masaüstündeki standart derlenmiş C#/Go/Rust yardımcı programı
            var analysis = new FileAnalysisResult
            {
                FileName = "network_benchmark.exe",
                FilePath = @"C:\Users\User\Desktop\network_benchmark.exe",
                IsExecutable = true,
                IsSigned = false,
                Entropy = 6.4,
                IsKnownLocation = false
            };

            var (score, level, reasons) = await _scoringEngine.CalculateRiskScoreAsync(analysis);

            Assert.True(score < 40, $"Expected score < 40 for desktop utility, but got {score}");
            Assert.Equal(RiskLevel.Clean, level);
            Assert.DoesNotContain(reasons, r => r.Contains("PUP/Crack/Keygen"));
        }

        [Fact]
        public async Task TrustedPublisher_CommercialSigned_ReceivesTrustDiscount()
        {
            // Senaryo: Google, Mozilla veya Valve tarafından imzalanmış ticari yazılım
            var analysis = new FileAnalysisResult
            {
                FileName = "chrome_installer.exe",
                FilePath = @"C:\Users\User\Downloads\chrome_installer.exe",
                IsExecutable = true,
                IsSigned = true,
                SignatureValid = true,
                SignaturePublisher = "Google LLC",
                Entropy = 6.8,
                IsKnownLocation = false
            };

            var (score, level, reasons) = await _scoringEngine.CalculateRiskScoreAsync(analysis);

            Assert.Equal(0, score);
            Assert.Equal(RiskLevel.Clean, level);
            Assert.Contains(reasons, r => r.Contains("Google LLC") || r.Contains("Doğrulanmış ticari yayımcı"));
        }

        [Fact]
        public void TrustedSoftwarePolicy_RecognizesLegitimateInstallLocations()
        {
            Assert.True(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Program Files\Google\Chrome\Application\chrome.exe"));
            Assert.True(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Program Files (x86)\Steam\steam.exe"));
            Assert.True(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe"));
            Assert.True(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Windows\System32\cmd.exe"));

            // Downloads ve Temp meşru kurulum lokasyonu değildir (Drop zone)
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Users\User\Downloads\test.exe"));
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Users\User\AppData\Local\Temp\evil.exe"));
        }

        [Fact]
        public void TrustedSoftwarePolicy_RecognizesMajorCommercialPublishers()
        {
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Google LLC"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Valve Corporation"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Mozilla Corporation"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("NVIDIA Corporation"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Discord Inc."));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Spotify AB"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Epic Games, Inc."));

            Assert.False(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Unknown Hacker Group"));
            Assert.False(TrustedSoftwarePolicy.IsTrustedCommercialPublisher(null));
        }

        [Fact]
        public async Task ActualMalware_EicarAndDoubleExtension_StillEnforcesDetection()
        {
            // 1. Double extension disguised payload -> Kesin Zararlı
            var doubleExtAnalysis = new FileAnalysisResult
            {
                FileName = "financial_statement.pdf.exe",
                FilePath = @"C:\Users\User\Downloads\financial_statement.pdf.exe",
                IsExecutable = true,
                IsSigned = false,
                Entropy = 7.1,
                IsKnownLocation = false
            };

            var (score, level, reasons) = await _scoringEngine.CalculateRiskScoreAsync(doubleExtAnalysis);
            Assert.True(score >= 85);
            Assert.Equal(RiskLevel.ConfirmedMalicious, level);
            Assert.Contains(reasons, r => r.Contains("Çift uzantı"));

            // 2. Hacktool / Keygen deseni -> HighRisk PUP
            var keygenAnalysis = new FileAnalysisResult
            {
                FileName = "software_keygen.exe",
                FilePath = @"C:\Users\User\Downloads\software_keygen.exe",
                IsExecutable = true,
                IsSigned = false,
                Entropy = 6.2,
                IsKnownLocation = false
            };

            var (kScore, kLevel, kReasons) = await _scoringEngine.CalculateRiskScoreAsync(keygenAnalysis);
            Assert.True(kScore >= 60);
            Assert.Equal(RiskLevel.HighRisk, kLevel);
            Assert.Contains(kReasons, r => r.Contains("PUP/Crack/Keygen"));
        }

        [Fact]
        public void ScanResourceProfile_ConcurrencyScaling_MatchesHardwareCapabilities()
        {
            int cores = 8;
            long ramBytes = 16L * 1024 * 1024 * 1024; // 16 GB

            // Balanced: SSD için cores * 2 (16 workers)
            var balanced = ScanResourceProfile.Create(ScanResourceMode.Balanced, false, cores, ramBytes);
            Assert.Equal(16, balanced.Concurrency);
            Assert.Equal(0, balanced.DelayBetweenFilesMs);
            Assert.Equal(0, balanced.YieldFrequency);

            // High: SSD için cores * 3 (24 workers)
            var high = ScanResourceProfile.Create(ScanResourceMode.High, false, cores, ramBytes);
            Assert.Equal(24, high.Concurrency);
            Assert.Equal(0, high.DelayBetweenFilesMs);
            Assert.Equal(65536, high.ChannelCapacity);

            // Maximum: SSD için cores * 4 (32 workers)
            var maximum = ScanResourceProfile.Create(ScanResourceMode.Maximum, false, cores, ramBytes);
            Assert.Equal(32, maximum.Concurrency);
            Assert.Equal(0, maximum.DelayBetweenFilesMs);
            Assert.Equal(65536, maximum.ChannelCapacity);

            // Mechanical HDD koruması aktifken:
            var hddBalanced = ScanResourceProfile.Create(ScanResourceMode.Balanced, true, cores, ramBytes);
            Assert.True(hddBalanced.Concurrency <= cores);
            Assert.True(hddBalanced.DelayBetweenFilesMs >= 2);
            Assert.True(hddBalanced.IsHddRestricted);
        }
    }
}
