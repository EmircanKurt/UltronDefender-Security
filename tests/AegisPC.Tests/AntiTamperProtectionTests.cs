using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Security.SelfDefense;
using Xunit;

namespace AegisPC.Tests
{
    public class AntiTamperProtectionTests
    {
        [Theory]
        [InlineData("cmd.exe", "sc config AegisPCProtectionService start= disabled", TamperType.ServiceConfigTamper)]
        [InlineData("cmd.exe", "sc.exe stop AegisPCProtectionService", TamperType.ServiceConfigTamper)]
        [InlineData("cmd.exe", "sc delete UltronDefenderService", TamperType.ServiceConfigTamper)]
        [InlineData("cmd.exe", @"reg add HKLM\SYSTEM\CurrentControlSet\Services\AegisPCProtectionService /v Start /t REG_DWORD /d 4 /f", TamperType.RegistryTamper)]
        [InlineData("powershell.exe", @"reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\AegisFilter /v Start /d 4 /f", TamperType.RegistryTamper)]
        [InlineData("cmd.exe", @"del /f /q ""C:\Program Files\UltronDefender\AegisPC.exe""", TamperType.BinaryDeletionTamper)]
        [InlineData("powershell.exe", @"Remove-Item -Path 'C:\Program Files\UltronDefender\aegisfilter.sys' -Force", TamperType.BinaryDeletionTamper)]
        [InlineData("cmd.exe", "fltmc unload AegisFilter", TamperType.DriverUnloadTamper)]
        [InlineData("cmd.exe", "fltmc.exe unload UltronFilter", TamperType.DriverUnloadTamper)]
        [InlineData(@"C:\Tools\ProcessHacker.exe", @"ProcessHacker.exe", TamperType.OffensiveToolTamper)]
        [InlineData(@"C:\Tools\procexp64.exe", @"procexp64.exe", TamperType.OffensiveToolTamper)]
        [InlineData(@"C:\Tools\PCHunter64.exe", @"PCHunter64.exe", TamperType.OffensiveToolTamper)]
        [InlineData("cmd.exe", "taskkill /f /im AegisPC.exe", TamperType.ProcessKillTamper)]
        [InlineData("powershell.exe", "stop-process -name AegisPC.Service -force", TamperType.ProcessKillTamper)]
        public void TamperDetector_DetectsAllPrescribedTamperingPatterns(string imagePath, string commandLine, TamperType expectedType)
        {
            bool detected = TamperDetector.CheckTamperPattern(
                imagePath,
                commandLine,
                out var detectedType,
                out var targetAsset,
                out var ruleName);

            Assert.True(detected, $"Tampering command must be detected: {commandLine}");
            Assert.Equal(expectedType, detectedType);
            Assert.False(string.IsNullOrEmpty(targetAsset), "Target asset must be populated");
            Assert.False(string.IsNullOrEmpty(ruleName), "Rule name must be populated");
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\notepad.exe", "notepad.exe C:\\my_notes.txt")]
        [InlineData(@"C:\Program Files\Git\bin\git.exe", "git.exe commit -m \"fix sc config typo\"")]
        [InlineData(@"C:\Windows\System32\cmd.exe", "dir C:\\Windows")]
        [InlineData(@"C:\Windows\System32\sc.exe", "sc.exe query Winmgmt")]
        public void TamperDetector_AllowsBenignAdministrativeCommands(string imagePath, string commandLine)
        {
            bool detected = TamperDetector.CheckTamperPattern(
                imagePath,
                commandLine,
                out var detectedType,
                out _,
                out _);

            Assert.False(detected, $"Benign command must not be flagged as tampering: {commandLine}");
            Assert.Equal(TamperType.None, detectedType);
        }

        [Fact]
        public void EventLogReader_ParsesSysmonEvent1XmlCorrectly()
        {
            string sysmonXml = @"
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                <System>
                    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}' />
                    <EventID>1</EventID>
                    <TimeCreated SystemTime='2026-09-08T12:00:00.000000000Z' />
                </System>
                <EventData>
                    <Data Name='ProcessId'>4580</Data>
                    <Data Name='ParentProcessId'>1200</Data>
                    <Data Name='Image'>C:\Windows\System32\cmd.exe</Data>
                    <Data Name='CommandLine'>cmd.exe /c sc config AegisPCProtectionService start= disabled</Data>
                    <Data Name='ParentImage'>C:\Windows\explorer.exe</Data>
                    <Data Name='User'>CORP\Attacker</Data>
                    <Data Name='UtcTime'>2026-09-08 12:00:00.000</Data>
                </EventData>
            </Event>";

            var parsed = EventLogReader.ParseSysmonEventXml(sysmonXml);

            Assert.NotNull(parsed);
            Assert.Equal(4580, parsed.ProcessId);
            Assert.Equal(1200, parsed.ParentProcessId);
            Assert.Equal(@"C:\Windows\System32\cmd.exe", parsed.ImagePath);
            Assert.Contains("sc config AegisPCProtectionService start= disabled", parsed.CommandLine);
            Assert.Equal("CORP\\Attacker", parsed.User);
            Assert.Equal("Sysmon-Event1", parsed.SourceLog);
        }

        [Fact]
        public void EventLogReader_ParsesSecurity4688XmlWithHexPidCorrectly()
        {
            string sec4688Xml = @"
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                <System>
                    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' />
                    <EventID>4688</EventID>
                </System>
                <EventData>
                    <Data Name='NewProcessId'>0x13ec</Data>
                    <Data Name='ProcessId'>0x400</Data>
                    <Data Name='NewProcessName'>C:\Windows\System32\fltmc.exe</Data>
                    <Data Name='CommandLine'>fltmc unload AegisFilter</Data>
                    <Data Name='ParentProcessName'>C:\Windows\System32\cmd.exe</Data>
                    <Data Name='SubjectUserName'>Administrator</Data>
                </EventData>
            </Event>";

            var parsed = EventLogReader.ParseSecurity4688EventXml(sec4688Xml);

            Assert.NotNull(parsed);
            // 0x13ec = 5100 decimal
            Assert.Equal(5100, parsed.ProcessId);
            // 0x400 = 1024 decimal
            Assert.Equal(1024, parsed.ParentProcessId);
            Assert.Equal(@"C:\Windows\System32\fltmc.exe", parsed.ImagePath);
            Assert.Equal("fltmc unload AegisFilter", parsed.CommandLine);
            Assert.Equal("Security-4688", parsed.SourceLog);
        }

        [Fact]
        public async Task TamperDetector_GeneratesCompleteTamperAlertAndSecurityFinding()
        {
            using var reader = new EventLogReader();
            using var detector = new TamperDetector(reader);
            detector.IsAutoContainmentEnabled = false; // Test ortamında gerçek süreç kapatılmasın

            TamperAlert? capturedAlert = null;
            detector.TamperDetected += alert => capturedAlert = alert;

            var maliciousEvent = new ProcessCreationEvent
            {
                ProcessId = 9999,
                ParentProcessId = 1111,
                ImagePath = @"C:\Windows\System32\sc.exe",
                CommandLine = "sc.exe config AegisPCProtectionService start= disabled",
                TimestampUtc = DateTime.UtcNow
            };

            var alertResult = await detector.HandleTamperDetectedAsync(
                maliciousEvent,
                TamperType.ServiceConfigTamper,
                "AegisPCProtectionService",
                "TAMPER-02: SC Config Servis Müdahalesi");

            Assert.NotNull(capturedAlert);
            Assert.Equal(9999, capturedAlert.OffendingProcessId);
            Assert.Equal(TamperType.ServiceConfigTamper, capturedAlert.TamperType);

            // SecurityFinding dönüşüm testi
            var finding = alertResult.ToSecurityFinding();
            Assert.NotNull(finding);
            Assert.Equal(100, finding.RiskScore);
            Assert.Equal(RiskLevel.ConfirmedMalicious, finding.RiskLevel);
            Assert.Equal(FindingCategory.SystemModification, finding.Category);
            Assert.Contains("Devre Dışı Bırakma", finding.Title);
            Assert.Contains(finding.RiskReasons, r => r.Contains("9999"));
        }
    }
}
