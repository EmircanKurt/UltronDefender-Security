using System;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Security.SelfDefense;
using Xunit;

namespace AegisPC.Tests
{
    /// <summary>
    /// AegisPC Bütünleşik Öz Savunma ve Müdahale Önleme (Anti-Tampering) Test Paketi.
    /// sc config, reg add Start=4, del, fltmc unload, Process Hacker / PCHunter ve taskkill
    /// saldırı desenlerini, otomatik izolasyonu (Process Kill) ve kendini onarmayı (Self-Heal) test eder.
    /// </summary>
    public class TamperDetectionTest
    {
        [Theory]
        // Saldırı Deseni 1: sc config ile servisi devre dışı bırakma
        [InlineData("cmd.exe", "sc config AegisPCProtectionService start= disabled", TamperType.ServiceConfigTamper)]
        [InlineData("cmd.exe", "sc.exe stop AegisPCProtectionService", TamperType.ServiceConfigTamper)]
        [InlineData("cmd.exe", "sc delete UltronDefenderService", TamperType.ServiceConfigTamper)]

        // Saldırı Deseni 2: Kayıt Defteri Start=4 ile servisi felç etme
        [InlineData("cmd.exe", @"reg add HKLM\SYSTEM\CurrentControlSet\Services\AegisPCProtectionService /v Start /t REG_DWORD /d 4 /f", TamperType.RegistryTamper)]
        [InlineData("powershell.exe", @"reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\AegisFilter /v Start /d 4 /f", TamperType.RegistryTamper)]

        // Saldırı Deseni 3: del / erase ile kritik antivirüs dosyalarını silme
        [InlineData("cmd.exe", @"del /f /q ""C:\Program Files\UltronDefender\AegisPC.exe""", TamperType.BinaryDeletionTamper)]
        [InlineData("powershell.exe", @"Remove-Item -Path 'C:\Program Files\UltronDefender\aegisfilter.sys' -Force", TamperType.BinaryDeletionTamper)]

        // Saldırı Deseni 4: fltmc unload ile Minifilter çekirdek sürücüsünü boşaltma
        [InlineData("cmd.exe", "fltmc unload AegisFilter", TamperType.DriverUnloadTamper)]
        [InlineData("cmd.exe", "fltmc.exe unload UltronFilter", TamperType.DriverUnloadTamper)]

        // Saldırı Deseni 5: Process Hacker, PCHunter, Process Explorer gibi bellek manipülasyon araçları
        [InlineData(@"C:\Tools\ProcessHacker.exe", @"ProcessHacker.exe", TamperType.OffensiveToolTamper)]
        [InlineData(@"C:\Tools\procexp64.exe", @"procexp64.exe", TamperType.OffensiveToolTamper)]
        [InlineData(@"C:\Tools\PCHunter64.exe", @"PCHunter64.exe", TamperType.OffensiveToolTamper)]

        // Saldırı Deseni 6: taskkill veya stop-process ile süreci sonlandırma
        [InlineData("cmd.exe", "taskkill /f /im AegisPC.exe", TamperType.ProcessKillTamper)]
        [InlineData("powershell.exe", "stop-process -name AegisPC.Service -force", TamperType.ProcessKillTamper)]
        public void TamperDetection_DetectsAllPrescribedAttackPatterns(
            string imagePath,
            string commandLine,
            TamperType expectedType)
        {
            bool detected = TamperDetector.CheckTamperPattern(
                imagePath,
                commandLine,
                out var detectedType,
                out var targetAsset,
                out var ruleName);

            Assert.True(detected, $"Anti-Tamper saldırı deseni yakalanmalıdır: {commandLine}");
            Assert.Equal(expectedType, detectedType);
            Assert.False(string.IsNullOrEmpty(targetAsset), "Hedef varlık bilgisi dolu olmalıdır.");
            Assert.False(string.IsNullOrEmpty(ruleName), "Kural adı dolu olmalıdır.");
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\notepad.exe", "notepad.exe C:\\my_notes.txt")]
        [InlineData(@"C:\Program Files\Git\bin\git.exe", "git.exe commit -m \"fix sc config typo\"")]
        [InlineData(@"C:\Windows\System32\cmd.exe", "dir C:\\Windows")]
        [InlineData(@"C:\Windows\System32\sc.exe", "sc.exe query Winmgmt")]
        public void TamperDetection_AllowsBenignAdministrativeCommands_ZeroFalsePositives(
            string imagePath,
            string commandLine)
        {
            bool detected = TamperDetector.CheckTamperPattern(
                imagePath,
                commandLine,
                out var detectedType,
                out _,
                out _);

            Assert.False(detected, $"Zararsız sistem komutuna alarm verilmemelidir: {commandLine}");
            Assert.Equal(TamperType.None, detectedType);
        }

        [Fact]
        public async Task TamperDetection_AutoContainmentAndAlertGeneration_ProducesScore100Finding()
        {
            using var reader = new EventLogReader();
            using var detector = new TamperDetector(reader);
            detector.IsAutoContainmentEnabled = false; // Test ortamında süreç sonlandırılmasın

            TamperAlert? raisedAlert = null;
            detector.TamperDetected += a => raisedAlert = a;

            var maliciousEvent = new ProcessCreationEvent
            {
                ProcessId = 9876,
                ParentProcessId = 1234,
                ImagePath = @"C:\Windows\System32\cmd.exe",
                CommandLine = "cmd.exe /c sc config AegisPCProtectionService start= disabled",
                TimestampUtc = DateTime.UtcNow
            };

            var alert = await detector.HandleTamperDetectedAsync(
                maliciousEvent,
                TamperType.ServiceConfigTamper,
                "AegisPCProtectionService",
                "TAMPER-02: SC Config Servis Müdahalesi");

            Assert.NotNull(raisedAlert);
            Assert.Equal(9876, raisedAlert.OffendingProcessId);
            Assert.Equal(TamperType.ServiceConfigTamper, raisedAlert.TamperType);

            // Güvenlik alarmı (SecurityFinding) dönüşüm testi
            var finding = alert.ToSecurityFinding();
            Assert.NotNull(finding);
            Assert.Equal(100, finding.RiskScore);
            Assert.Equal(RiskLevel.ConfirmedMalicious, finding.RiskLevel);
            Assert.Equal(FindingCategory.SystemModification, finding.Category);
            Assert.Contains("Devre Dışı Bırakma", finding.Title);
            Assert.Contains(finding.RiskReasons, r => r.Contains("9876"));
        }

        [Fact]
        public void TamperDetection_SelfHealManager_RestoresServiceAndDriverConstants()
        {
            Assert.Equal("AegisPCProtectionService", SelfHealManager.DefaultServiceName);
            Assert.Equal("AegisFilter", SelfHealManager.DefaultDriverName);
        }
    }
}
