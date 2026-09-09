using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AegisPC.Core.Helpers;
using AegisPC.Service.Network;
using AegisPC.Service.SmartScreen;
using Xunit;

namespace AegisPC.Tests
{
    public class OfflineDnsAndUrlFilteringTests : IDisposable
    {
        private readonly string _tempDirectory;
        private readonly string _tempHostsPath;

        public OfflineDnsAndUrlFilteringTests()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), $"AegisDnsTests_{Guid.NewGuid():N}");
            Directory.CreateDirectory(_tempDirectory);
            _tempHostsPath = Path.Combine(_tempDirectory, "hosts");

            // Orijinal hosts içeriği simülasyonu
            File.WriteAllText(_tempHostsPath, "# Standard Windows Hosts\r\n127.0.0.1 localhost\r\n::1 localhost\r\n192.168.1.1 router.local\r\n");
        }

        [Fact]
        public void HostsInjectionHelper_AppliesSinkholeWithBackupAndRollback()
        {
            var helper = new HostsInjectionHelper(_tempHostsPath);

            var domains = new[]
            {
                ("evil-c2.net", "C2Server"),
                ("phish-login.com", "Phishing"),
                ("miner-pool.org", "CryptoMining")
            };

            // 1. Enjeksiyon
            bool applied = helper.ApplySinkhole(domains, SinkholeIpMode.Loopback);
            Assert.True(applied);
            Assert.True(helper.IsSinkholeActive());
            Assert.Equal(3, helper.GetSinkholeEntryCount());

            string injectedContent = File.ReadAllText(_tempHostsPath);
            Assert.Contains(HostsInjectionHelper.SinkholeMarkerBegin, injectedContent);
            Assert.Contains("127.0.0.1 evil-c2.net", injectedContent);
            Assert.Contains("127.0.0.1 phish-login.com", injectedContent);
            Assert.Contains("127.0.0.1 miner-pool.org", injectedContent);
            Assert.Contains("router.local", injectedContent); // Orijinal satırlar korunmalı

            // Yedek dosyası oluşturulmuş olmalı
            Assert.True(File.Exists(helper.BackupFilePath));

            // 2. Sinkhole Kaldırma
            bool removed = helper.RemoveSinkhole();
            Assert.True(removed);
            Assert.False(helper.IsSinkholeActive());
            Assert.Equal(0, helper.GetSinkholeEntryCount());

            string cleanedContent = File.ReadAllText(_tempHostsPath);
            Assert.DoesNotContain(HostsInjectionHelper.SinkholeMarkerBegin, cleanedContent);
            Assert.Contains("router.local", cleanedContent);

            // 3. Yedekten Geri Yükleme
            bool restored = helper.RestoreBackup();
            Assert.True(restored);
            string restoredContent = File.ReadAllText(_tempHostsPath);
            Assert.Contains("192.168.1.1 router.local", restoredContent);
        }

        [Theory]
        [InlineData("c2-redline-stealer.biz", UrlBlockCategory.C2Server)]
        [InlineData("subdomain.c2-redline-stealer.biz", UrlBlockCategory.C2Server)]
        [InlineData("paypa1-security-check.com", UrlBlockCategory.Phishing)]
        [InlineData("login.paypa1-security-check.com", UrlBlockCategory.Phishing)]
        [InlineData("coinhive.com", UrlBlockCategory.CryptoMining)]
        [InlineData("malvertising-traffic-hub.top", UrlBlockCategory.Malvertising)]
        public void UrlBlocklistManager_DetectsExactAndSubdomainMatches(string query, UrlBlockCategory expectedCategory)
        {
            var manager = new UrlBlocklistManager(_tempDirectory);

            var res = manager.EvaluateUrl(query);
            Assert.True(res.IsBlocked, $"Query should be blocked: {query}");
            Assert.Equal(expectedCategory, res.Category);
            Assert.True(res.RiskScore >= 70);
        }

        [Fact]
        public void UrlBlocklistManager_AllowsCleanDomains()
        {
            var manager = new UrlBlocklistManager(_tempDirectory);

            var res1 = manager.EvaluateUrl("https://www.microsoft.com/en-us/windows");
            var res2 = manager.EvaluateUrl("https://google.com");
            var res3 = manager.EvaluateUrl("https://github.com/torvalds/linux");

            Assert.False(res1.IsBlocked);
            Assert.False(res2.IsBlocked);
            Assert.False(res3.IsBlocked);
            Assert.Equal(0, res1.RiskScore);
        }

        [Fact]
        public void UrlBlocklistManager_ParsesDiverseFormats()
        {
            var manager = new UrlBlocklistManager(_tempDirectory);

            // Hosts formatı
            manager.AddRule("127.0.0.1 custom-hosts-bad.com", UrlBlockCategory.C2Server);
            // Adblock formatı
            manager.AddRule("||adnetwork-tracker.xyz^", UrlBlockCategory.Malvertising);
            // Regex formatı
            manager.AddRule("regex:^https?:\\/\\/.*\\/stealer\\/gate\\.php", UrlBlockCategory.C2Server);

            Assert.True(manager.EvaluateUrl("custom-hosts-bad.com").IsBlocked);
            Assert.True(manager.EvaluateUrl("sub.custom-hosts-bad.com").IsBlocked);
            Assert.True(manager.EvaluateUrl("adnetwork-tracker.xyz").IsBlocked);
            Assert.True(manager.EvaluateUrl("https://unknown-domain.net/stealer/gate.php?id=123").IsBlocked);
        }

        [Fact]
        public void ZoneIdentifierAnalyzer_ParsesZoneTransferAndCorrelatesWithBlocklists()
        {
            var manager = new UrlBlocklistManager(_tempDirectory);
            var analyzer = new ZoneIdentifierAnalyzer(manager);

            // Temiz internet indirmesi
            string cleanContent = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://download.microsoft.com/installer.exe\r\nReferrerUrl=https://www.microsoft.com";
            var cleanResult = analyzer.ParseZoneIdentifierContent(cleanContent, "installer.exe");
            Assert.True(cleanResult.HasZoneIdentifier);
            Assert.True(cleanResult.IsFromInternet);
            Assert.False(cleanResult.IsBlockedOrigin);
            Assert.Equal(SecurityZone.Internet, cleanResult.Zone);

            // Zararlı C2 kökenli indirme
            string c2Content = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://c2-redline-stealer.biz/payload.exe\r\nReferrerUrl=https://innocent-looking-site.com";
            var c2Result = analyzer.ParseZoneIdentifierContent(c2Content, "payload.exe");
            Assert.True(c2Result.HasZoneIdentifier);
            Assert.True(c2Result.IsBlockedOrigin);
            Assert.Equal(UrlBlockCategory.C2Server, c2Result.OriginCategory);
            Assert.Equal(100, c2Result.RiskScore);
            Assert.Contains("engelli kaynaktan", c2Result.BlockReason);

            // Zararlı Oltalama (Phishing) yönlendirmeli indirme
            string phishContent = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://cdn.somefilehost.com/invoice.exe\r\nReferrerUrl=https://paypa1-security-check.com/login";
            var phishResult = analyzer.ParseZoneIdentifierContent(phishContent, "invoice.exe");
            Assert.True(phishResult.HasZoneIdentifier);
            Assert.True(phishResult.IsBlockedOrigin);
            Assert.Equal(UrlBlockCategory.Phishing, phishResult.OriginCategory);
            Assert.Equal(95, phishResult.RiskScore);
        }

        [Fact]
        public async Task DnsFilterService_ResolvesToLocalSinkholeForBlockedDomains()
        {
            var manager = new UrlBlocklistManager(_tempDirectory);
            var hostsHelper = new HostsInjectionHelper(_tempHostsPath);
            using var dnsService = new DnsFilterService(manager, hostsHelper);

            // Zararlı C2 sorgusu
            var result = await dnsService.ResolveDomainAsync("c2-redline-stealer.biz", useDohIfOnline: false);

            Assert.True(result.IsBlocked);
            Assert.Equal(UrlBlockCategory.C2Server, result.BlockCategory);
            Assert.Equal("Local-Sinkhole", result.ResolutionSource);
            Assert.Contains(IPAddress.Parse("127.0.0.1"), result.ResolvedAddresses);

            var stats = dnsService.GetStatistics();
            Assert.True(stats.TotalDomainRules > 0);
            Assert.True(stats.BlockedQueriesCount >= 1);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempDirectory))
                {
                    Directory.Delete(_tempDirectory, recursive: true);
                }
            }
            catch { }
        }
    }
}
