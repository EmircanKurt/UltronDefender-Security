using System.Threading.Tasks;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class WebShieldTests
    {
        private readonly WebShieldService _webShield = new();

        [Theory]
        [InlineData("https://www.paypal.com/signin")]
        [InlineData("https://login.microsoft.com/oauth")]
        [InlineData("https://github.com/login")]
        [InlineData("https://google.com/search?q=test")]
        public async Task AnalyzeUrl_OfficialAndWhitelistedDomains_ReturnsCleanAndNotBlocked(string url)
        {
            var verdict = await _webShield.AnalyzeUrlAsync(url);

            Assert.False(verdict.IsBlocked);
            Assert.False(verdict.IsPhishing);
            Assert.Equal(0, verdict.RiskScore);
        }

        [Theory]
        [InlineData("http://paypa1-verify-account.com")]
        [InlineData("http://micros0ft-alert-system.top")]
        [InlineData("http://steamc0mmunity-trade.xyz")]
        public async Task AnalyzeUrl_TyposquattingPhishingDomains_FlaggedAsPhishingAndBlocked(string url)
        {
            var verdict = await _webShield.AnalyzeUrlAsync(url);

            Assert.True(verdict.IsBlocked);
            Assert.True(verdict.IsPhishing);
            Assert.True(verdict.RiskScore >= 60);
            Assert.NotEmpty(verdict.DetectionReasons);
        }

        [Fact]
        public async Task AnalyzeUrl_HomographPunycodeAttack_FlaggedAsPhishing()
        {
            string punycodeUrl = "https://xn--pple-43d.com/login";
            var verdict = await _webShield.AnalyzeUrlAsync(punycodeUrl);

            Assert.True(verdict.IsBlocked);
            Assert.True(verdict.IsPhishing);
            Assert.Contains(verdict.DetectionReasons, r => r.Contains("Punycode"));
        }

        [Fact]
        public async Task AnalyzeUrl_SuspiciousTldWithAuthKeywords_FlaggedAsPhishing()
        {
            string url = "http://secure-account-banking-checkpoint.top/login.html";
            var verdict = await _webShield.AnalyzeUrlAsync(url);

            Assert.True(verdict.IsBlocked);
            Assert.True(verdict.IsPhishing);
            Assert.True(verdict.RiskScore >= 60);
        }

        [Fact]
        public async Task AnalyzeUrl_DangerousExecutableDownload_FlaggedAsDangerous()
        {
            string url = "http://freedownloads.xyz/malicious_payload.exe";
            var verdict = await _webShield.AnalyzeUrlAsync(url);

            Assert.True(verdict.IsDangerousDownload);
            Assert.Contains(verdict.DetectionReasons, r => r.Contains("çalıştırılabilir"));
        }

        [Fact]
        public async Task AddAndRemoveBypassDomain_FunctionsCorrectly()
        {
            string testDomain = "custom-internal-portal.local";
            
            bool added = _webShield.AddBypassDomain(testDomain);
            Assert.True(added);
            Assert.Contains(testDomain, _webShield.GetBypassDomains());

            var verdict = await _webShield.AnalyzeUrlAsync($"http://{testDomain}/login");
            Assert.False(verdict.IsBlocked);
            Assert.Equal(0, verdict.RiskScore);

            bool removed = _webShield.RemoveBypassDomain(testDomain);
            Assert.True(removed);
            Assert.DoesNotContain(testDomain, _webShield.GetBypassDomains());
        }
    }
}
