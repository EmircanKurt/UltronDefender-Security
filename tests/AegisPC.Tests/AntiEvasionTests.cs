using System;
using System.Text;
using AegisPC.Contracts.AntiEvasion;
using AegisPC.Security.AntiEvasion;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class AntiEvasionTests
    {
        [Fact]
        public void Test_AntiEvasionDetector_DetectsAntiDebuggingApis()
        {
            var detector = new AntiEvasionDetector();
            var payload = "IMPORT_TABLE: IsDebuggerPresent(); CheckRemoteDebuggerPresent(); NtSetInformationThread(); OutputDebugStringA();";
            var bytes = Encoding.ASCII.GetBytes(payload);

            var eval = detector.AnalyzeBinary("dummy_test.exe", bytes);

            Assert.True(eval.HasEvasionTechniques);
            Assert.True((eval.DetectedTechniques & AntiEvasionTechnique.AntiDebugging) != 0);
            Assert.True(eval.EvasionScore >= 40);
            Assert.Contains(eval.TechniqueDescriptions, d => d.Contains("IsDebuggerPresent"));
        }

        [Fact]
        public void Test_AntiEvasionDetector_DetectsAntiVmArtifacts()
        {
            var detector = new AntiEvasionDetector();
            var payload = @"QUERY_DRIVER: vboxmouse.sys; vmmouse.sys; REG_KEY: HARDWARE\DESCRIPTION\System\BIOS";
            var bytes = Encoding.ASCII.GetBytes(payload);

            var eval = detector.AnalyzeBinary("sandbox_evasion.exe", bytes);

            Assert.True(eval.HasEvasionTechniques);
            Assert.True((eval.DetectedTechniques & AntiEvasionTechnique.AntiVmHypervisor) != 0);
            Assert.True(eval.EvasionScore >= 40);
            Assert.Contains(eval.TechniqueDescriptions, d => d.Contains("vboxmouse.sys"));
        }

        [Fact]
        public void Test_AntiEvasionDetector_DetectsAmsiEtwPatchingSignatures()
        {
            var detector = new AntiEvasionDetector();
            var payload = "PATCH_TARGET: amsiInitFailed = true; [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'); EtwEventWrite";
            var bytes = Encoding.ASCII.GetBytes(payload);

            var eval = detector.AnalyzeBinary("evader.ps1", bytes);

            Assert.True(eval.HasEvasionTechniques);
            Assert.True((eval.DetectedTechniques & AntiEvasionTechnique.AmsiEtwPatching) != 0);
            Assert.True(eval.EvasionScore >= 50);
            Assert.Contains(eval.TechniqueDescriptions, d => d.Contains("amsiInitFailed"));
        }

        [Fact]
        public void Test_AntiEvasionDetector_DetectsIndirectSyscallStubs()
        {
            var detector = new AntiEvasionDetector();
            
            // Construct raw indirect syscall machine code sequence:
            // 4C 8B D1 (mov r10, rcx) -> B8 18 00 00 00 (mov eax, 0x18) -> 0F 05 (syscall) -> C3 (ret)
            var rawBytes = new byte[]
            {
                0x90, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00,
                0x0F, 0x05, 0xC3,
                0x90, 0x90
            };

            var eval = detector.AnalyzeBinary("hellsgate_stub.bin", rawBytes);

            Assert.True(eval.HasEvasionTechniques);
            Assert.True((eval.DetectedTechniques & AntiEvasionTechnique.IndirectSyscallStubs) != 0);
            Assert.True(eval.EvasionScore >= 35);
            Assert.Contains(eval.TechniqueDescriptions, d => d.Contains("Indirect Syscall"));
        }

        [Fact]
        public void Test_AntiEvasionDetector_BehavioralCommandLine_AmsiBypass()
        {
            var detector = new AntiEvasionDetector();
            var cmdLine = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'); Start-Sleep -s 300\"";

            var eval = detector.AnalyzeBehavior(1234, cmdLine);

            Assert.True(eval.HasEvasionTechniques);
            Assert.True((eval.DetectedTechniques & AntiEvasionTechnique.AmsiEtwPatching) != 0);
            Assert.True((eval.DetectedTechniques & AntiEvasionTechnique.TimingSleepDelay) != 0);
            Assert.True(eval.EvasionScore >= 50);
        }

        [Fact]
        public void Test_MemoryPatternScanner_DetectsCobaltStrikeReflectiveLoader()
        {
            var scanner = new MemoryPatternScanner();

            // Embed Cobalt Strike signature inside a memory buffer
            var buffer = new byte[1024];
            var sig = new byte[] { 0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC };
            Array.Copy(sig, 0, buffer, 128, sig.Length);

            var verdict = scanner.ScanBuffer(buffer);

            Assert.True(verdict.IsMaliciousMemoryFound);
            Assert.Equal("Beacon", verdict.ThreatCategory);
            Assert.Equal(100, verdict.SeverityScore);
            Assert.Equal(128ul, verdict.MemoryAddress);
            Assert.Contains("CobaltStrike", verdict.MatchedPattern);
        }

        [Fact]
        public void Test_MemoryPatternScanner_DetectsMeterpreterStagers()
        {
            var scanner = new MemoryPatternScanner();

            // Meterpreter x64 payload
            var buffer = new byte[512];
            var sig = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00 };
            Array.Copy(sig, 0, buffer, 64, sig.Length);

            var verdict = scanner.ScanBuffer(buffer);

            Assert.True(verdict.IsMaliciousMemoryFound);
            Assert.Equal("Shellcode", verdict.ThreatCategory);
            Assert.Equal(95, verdict.SeverityScore);
            Assert.Equal(64ul, verdict.MemoryAddress);
            Assert.Contains("Meterpreter", verdict.MatchedPattern);
        }

        [Fact]
        public void Test_MemoryPatternScanner_DetectsAmsiPatchSignatures()
        {
            var scanner = new MemoryPatternScanner();

            var buffer = new byte[256];
            var patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // E_INVALIDARG patch
            Array.Copy(patch, 0, buffer, 32, patch.Length);

            var verdict = scanner.ScanBuffer(buffer);

            Assert.True(verdict.IsMaliciousMemoryFound);
            Assert.Equal("DefenseEvasion", verdict.ThreatCategory);
            Assert.Equal(90, verdict.SeverityScore);
            Assert.Contains("AMSI", verdict.MatchedPattern);
        }

        [Fact]
        public void Test_CleanBuffer_ReturnsCleanVerdict()
        {
            var scanner = new MemoryPatternScanner();
            var cleanBytes = Encoding.ASCII.GetBytes("This is a totally normal and benign program memory buffer.");

            var verdict = scanner.ScanBuffer(cleanBytes);

            Assert.False(verdict.IsMaliciousMemoryFound);
            Assert.Equal(0, verdict.SeverityScore);
            Assert.Empty(verdict.Evidences);
        }
    }
}
