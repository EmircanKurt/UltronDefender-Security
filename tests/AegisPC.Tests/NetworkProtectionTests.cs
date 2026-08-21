using System;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class NetworkProtectionTests
    {
        private readonly WebShieldService _webShield = new();

        [Fact]
        public async Task Test_DomainBlacklist_BlocksMaliciousDomain()
        {
            var verdict = await _webShield.AnalyzeUrlAsync("http://paypa1-security-check.com/login");
            Assert.True(verdict.IsBlocked);
            Assert.True(verdict.RiskScore >= 60);
            Assert.True(verdict.IsPhishing);
            Assert.NotEmpty(verdict.DetectionReasons);
        }

        [Fact]
        public async Task Test_CleanDomain_AllowedWithZeroScore()
        {
            var verdict = await _webShield.AnalyzeUrlAsync("https://www.microsoft.com/en-us/windows");
            Assert.False(verdict.IsBlocked);
            Assert.Equal(0, verdict.RiskScore);
        }

        [Fact]
        public async Task Test_BypassList_CustomDomainAddedAndAllowed()
        {
            string customDomain = "my-internal-company-portal.xyz";
            
            // Before bypass: high risk due to .xyz TLD + keywords
            _webShield.AddBypassDomain(customDomain);
            Assert.Contains(customDomain, _webShield.GetBypassDomains());

            var verdict = await _webShield.AnalyzeUrlAsync($"https://{customDomain}/login");
            Assert.False(verdict.IsBlocked);
            Assert.Equal(0, verdict.RiskScore);
        }

        [Fact]
        public async Task Test_PunycodeHomograph_TriggersHighRisk()
        {
            var verdict = await _webShield.AnalyzeUrlAsync("https://xn--pple-43d.com/login");
            Assert.True(verdict.RiskScore >= 60);
            Assert.True(verdict.IsPhishing);
            Assert.Contains(verdict.DetectionReasons, r => r.Contains("Punycode") || r.Contains("Homograph"));
        }

        [Fact]
        public async Task Test_DnsAdapters_Enumeration()
        {
            using var dnsService = new DnsProtectionService(_webShield);
            var adapters = await dnsService.GetNetworkAdaptersDnsAsync();
            Assert.NotNull(adapters);
        }

        [Fact]
        public async Task Test_HostsFileIntegrity_Check()
        {
            using var dnsService = new DnsProtectionService(_webShield);
            var status = await dnsService.CheckHostsFileIntegrityAsync();
            Assert.NotNull(status);
        }
    }
}
