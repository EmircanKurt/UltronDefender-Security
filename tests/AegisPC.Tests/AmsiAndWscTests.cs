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

        public void Dispose()
        {
            _amsiService.Dispose();
        }
    }
}
