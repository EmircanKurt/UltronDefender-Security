using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using AegisPC.App.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Xunit;

namespace AegisPC.Tests
{
    public class ScanReportGeneratorTests
    {
        [Fact]
        public void GenerateTextReport_WithFindings_ContainsAllRequiredFields()
        {
            // Arrange
            var scanDate = new DateTime(2026, 9, 10, 16, 30, 0);
            string duration = "00:02:15";
            string scanType = "Hızlı Tarama";
            int scannedCount = 1450;

            var finding = new SecurityFinding
            {
                Title = "Trojan.Win32.GenericMalware",
                RiskScore = 95,
                Category = FindingCategory.KnownMalwareHash,
                ObjectPath = @"C:\Users\TestUser\Downloads\malicious_payload.exe",
                Description = "Zararlı trojan tespit edildi ve sistemden izole edildi.",
                Status = FindingStatus.Resolved
            };

            var findings = new List<SecurityFinding> { finding };

            // Act
            string report = ScanReportGenerator.GenerateTextReport(
                scanDate,
                duration,
                scanType,
                scannedCount,
                findings);

            // Assert
            Assert.Contains("2026-09-10", report);
            Assert.Contains("00:02:15", report);
            Assert.Contains("Hızlı Tarama", report);
            Assert.Contains(scannedCount.ToString("N0"), report);
            Assert.Contains("Trojan.Win32.GenericMalware", report);
            Assert.Contains("95", report);
            Assert.Contains(FindingCategory.KnownMalwareHash.ToString(), report);
            Assert.Contains(@"C:\Users\TestUser\Downloads\malicious_payload.exe", report);
            Assert.Contains("Alınan Aksiyon", report);
            Assert.Contains("Olay kapatıldı (karantina doğrulanmadı)", report);
            Assert.Contains("Zararlı trojan tespit edildi ve sistemden izole edildi.", report);
        }

        [Fact]
        public void GenerateTextReport_EmptyDescription_UsesCategoryFallback()
        {
            // Arrange
            var finding = new SecurityFinding
            {
                Title = "Suspicious.Script.Dropper",
                RiskScore = 70,
                Category = FindingCategory.SuspiciousScript,
                ObjectPath = @"C:\temp\script.ps1",
                Description = "", // Empty description
                Status = FindingStatus.Active
            };

            var findings = new List<SecurityFinding> { finding };

            // Act
            string report = ScanReportGenerator.GenerateTextReport(
                DateTime.Now,
                "00:00:45",
                "Özel Tarama",
                300,
                findings);

            // Assert
            string expectedFallback = $"{finding.Category} kategorisinde tespit edilen güvenlik bulgusu.";
            Assert.Contains(expectedFallback, report);
            Assert.Contains("Suspicious.Script.Dropper", report);
            Assert.Contains(@"C:\temp\script.ps1", report);
        }

        [Fact]
        public async Task GenerateTextReport_SaveToTempFile_VerifyFileContent()
        {
            // Requirement 5: Test: üretilen raporu örnek bulgularla %TEMP% dizinine kaydet
            // ve içeriğin tehdit başlığı ile dosya yolunu içerdiğini doğrula.
            string tempDir = Path.GetTempPath();
            string tempFile = Path.Combine(tempDir, $"TestReport_{Guid.NewGuid():N}.txt");

            try
            {
                var finding = new SecurityFinding
                {
                    Title = "Ransom.Win32.WannaCrySample",
                    RiskScore = 100,
                    Category = FindingCategory.ConfirmedMalicious,
                    ObjectPath = @"C:\MalwareSamples\wannacry_test.bin",
                    Description = "Fidye yazılımı imzası yakalandı.",
                    Status = FindingStatus.Resolved
                };

                var findings = new List<SecurityFinding> { finding };

                string reportText = ScanReportGenerator.GenerateTextReport(
                    DateTime.Now,
                    "00:01:10",
                    "Tam Tarama",
                    5200,
                    findings);

                await File.WriteAllTextAsync(tempFile, reportText);

                // Verify file exists and content matches
                Assert.True(File.Exists(tempFile));
                string loadedContent = await File.ReadAllTextAsync(tempFile);
                Assert.Contains("Ransom.Win32.WannaCrySample", loadedContent);
                Assert.Contains(@"C:\MalwareSamples\wannacry_test.bin", loadedContent);
                Assert.Contains("ConfirmedMalicious", loadedContent);
                Assert.Contains("100", loadedContent);
            }
            finally
            {
                if (File.Exists(tempFile))
                {
                    File.Delete(tempFile);
                }
            }
        }

        [Fact]
        public void GetDefaultReportFileName_MatchesExpectedFormat()
        {
            // Requirement 1: varsayılan dosya adı: "UltronDefender_Rapor_yyyyMMdd_HHmm.txt"
            var testTime = new DateTime(2026, 9, 10, 14, 35, 12);
            string fileName = ScanReportGenerator.GetDefaultReportFileName(testTime);

            Assert.Equal("UltronDefender_Rapor_20260910_1435.txt", fileName);
        }

        [Fact]
        public void GetSuggestedInitialDirectory_DefaultFallsBackToDesktop()
        {
            // If no removable drives provided, fallback to Desktop
            string dir = ScanReportGenerator.GetSuggestedInitialDirectory(() => Array.Empty<DriveInfo>());
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            Assert.Equal(desktop, dir);
        }

        [Fact]
        public void GetSuggestedInitialDirectory_WithoutParameters_ReturnsValidDirectory()
        {
            string dir = ScanReportGenerator.GetSuggestedInitialDirectory();
            Assert.False(string.IsNullOrWhiteSpace(dir));
            Assert.True(Directory.Exists(dir));
        }

        [Fact]
        public void GenerateTextReport_DuplicateLocationsAndActionOverrides_GeneratesWithoutExceptions()
        {
            // Scenario from real scan: duplicate paths detected in findings
            string dupPath = @"C:\Users\PC\AppData\Roaming\npm\node_modules\@angular\cli\node_modules\esbuild\esbuild.exe";
            var findings = new List<SecurityFinding>
            {
                new SecurityFinding
                {
                    Title = "Kötücül Yazılım (Memory)",
                    RiskScore = 90,
                    Category = FindingCategory.ConfirmedMalicious,
                    ObjectPath = dupPath,
                    Status = FindingStatus.Active
                },
                new SecurityFinding
                {
                    Title = "Kötücül Yazılım (Disk)",
                    RiskScore = 85,
                    Category = FindingCategory.ConfirmedMalicious,
                    ObjectPath = dupPath,
                    Status = FindingStatus.Active
                }
            };

            // Ensure dictionary population with duplicate keys (simulating fixed actionMap logic)
            var actionMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            actionMap[dupPath] = "Uyarıldı";

            string report = ScanReportGenerator.GenerateTextReport(
                DateTime.Now,
                "00:03:12",
                "Hızlı Tarama",
                25000,
                findings,
                actionMap);

            Assert.Contains("Kötücül Yazılım (Memory)", report);
            Assert.Contains("Kötücül Yazılım (Disk)", report);
            Assert.Contains(dupPath, report);
            Assert.Contains("Uyarıldı", report);
            Assert.Contains("2 Güvenlik Bulgusu Tespit Edildi", report);
        }

        [Fact]
        public void GenerateTextReport_EmptyTitleAndCustomObjectName_RendersCorrectFallback()
        {
            var finding = new SecurityFinding
            {
                Title = "",
                ObjectName = "esbuild.exe",
                ObjectPath = @"C:\tools\esbuild.exe",
                RiskScore = 80,
                Category = FindingCategory.MalwareSuspicion,
                Status = FindingStatus.Active
            };

            string report = ScanReportGenerator.GenerateTextReport(
                DateTime.Now,
                "00:01:00",
                "Hızlı Tarama",
                100,
                new List<SecurityFinding> { finding });

            Assert.Contains("Tehdit Adı     : esbuild.exe", report);
            Assert.Contains(@"C:\tools\esbuild.exe", report);
        }
    }
}
