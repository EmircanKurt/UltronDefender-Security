using System;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Infrastructure;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class AmsiAndWscTests : IDisposable
    {
        private readonly AmsiScanService _amsiService;
        private readonly WindowsSecurityRegistrationService _wscService;

        public AmsiAndWscTests()
        {
            _amsiService = new AmsiScanService();
            _wscService = new WindowsSecurityRegistrationService();
        }

        [Fact]
        public async Task Test_AmsiScanService_EicarScript_DetectedAsMalicious()
        {
            var eicarScript = "Write-Host 'Starting...'; $payload = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'; Invoke-Expression $payload";
            
            var result = await _amsiService.ScanStringAsync(eicarScript, "TestEicarScript.ps1");

            Assert.NotNull(result);
            Assert.True(result.IsMalicious, "EICAR script MUST be flagged as malicious by AMSI / Script Engine");
            Assert.Equal(AmsiDetectionResult.Malicious, result.Result);
        }

        [Fact]
        public async Task Test_AmsiScanService_BenignScript_CleanVerdict()
        {
            var benignScript = "Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object Name, CPU";

            var result = await _amsiService.ScanStringAsync(benignScript, "BenignAdminScript.ps1");

            Assert.NotNull(result);
            Assert.False(result.IsMalicious, "Benign administrative PowerShell script must NOT be flagged as malicious");
            Assert.Equal(AmsiDetectionResult.Clean, result.Result);
        }

        [Fact]
        public async Task Test_AmsiScanService_ObfuscatedAmsiBypass_Detected()
        {
            var bypassScript = "$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'); $f = $a.GetField('amsiInitFailed','NonPublic,Static'); $f.SetValue($null,$true)";

            var result = await _amsiService.ScanStringAsync(bypassScript, "MaliciousBypass.ps1");

            Assert.NotNull(result);
            Assert.True(result.IsMalicious, "AMSI bypass attempt must be detected and blocked");
        }

        [Fact]
        public async Task Test_WindowsSecurityRegistrationService_QueriesAntivirusProducts()
        {
            var status = await _wscService.GetWindowsSecurityStatusAsync();

            Assert.NotNull(status);
            // On a standard Windows machine, WSC should return products or report status safely without crashing
            Assert.NotNull(status.StatusSummary);
            Assert.NotNull(status.RegisteredProducts);
        }

        [Fact]
        public void Test_WindowsSecurityRegistrationService_RegistrationExecutesSafely()
        {
            // Verify provider registration executes without unhandled exceptions
            var exception = Record.Exception(() => _wscService.RegisterAsSecurityProvider());
            Assert.Null(exception);
        }

        [Fact]
        public async Task Test_AmsiScanService_ScanBufferAsync_DetectsEicarPayload()
        {
            var eicarBytes = System.Text.Encoding.UTF8.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
            var result = await _amsiService.ScanBufferAsync(eicarBytes, "MemoryEicar.bin");

            Assert.NotNull(result);
            Assert.True(result.IsMalicious);
            Assert.Equal(AmsiDetectionResult.Malicious, result.Result);
        }

        [Fact]
        public async Task Test_AmsiScanService_ScanBufferAsync_AllowsBenignPayload()
        {
            var benignBytes = System.Text.Encoding.UTF8.GetBytes("Write-Output 'Hello from benign memory stream'");
            var result = await _amsiService.ScanBufferAsync(benignBytes, "BenignMemory.bin");

            Assert.NotNull(result);
            Assert.False(result.IsMalicious);
            Assert.Equal(AmsiDetectionResult.Clean, result.Result);
        }

        [Fact]
        public void Test_AmsiProvider_RegistrationScript_And_Clsid_Consistency()
        {
            string? repoRoot = AppContext.BaseDirectory;
            while (!string.IsNullOrEmpty(repoRoot) && 
                   !System.IO.File.Exists(System.IO.Path.Combine(repoRoot, "AegisPC.sln")) && 
                   !System.IO.Directory.Exists(System.IO.Path.Combine(repoRoot, ".git")))
            {
                repoRoot = System.IO.Path.GetDirectoryName(repoRoot);
            }

            Assert.NotNull(repoRoot);

            var scriptPath = System.IO.Path.GetFullPath(System.IO.Path.Combine(repoRoot, "tools/AmsiProvider/Register-AmsiProvider.ps1"));
            var headerPath = System.IO.Path.GetFullPath(System.IO.Path.Combine(repoRoot, "tools/AmsiProvider/AmsiProvider.h"));

            Assert.True(System.IO.File.Exists(scriptPath), $"AMSI registration script must exist: {scriptPath}");
            Assert.True(System.IO.File.Exists(headerPath), $"AMSI provider header must exist: {headerPath}");

            var scriptContent = System.IO.File.ReadAllText(scriptPath);
            var headerContent = System.IO.File.ReadAllText(headerPath);

            const string expectedClsid = "{638DC8E4-1B1C-4328-8C67-DF52445EFA10}";

            Assert.Contains(expectedClsid, scriptContent, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(expectedClsid, headerContent, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("-Verify", scriptContent);
            Assert.Contains("-Unregister", scriptContent);
            Assert.Contains("-DllPath", scriptContent);
        }

        public void Dispose()
        {
            _amsiService.Dispose();
        }
    }
}
