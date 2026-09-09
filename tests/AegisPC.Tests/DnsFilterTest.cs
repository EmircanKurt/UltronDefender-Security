using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using AegisPC.Core.Helpers;
using AegisPC.Service.Network;
using AegisPC.Service.SmartScreen;
using Xunit;

namespace AegisPC.Tests
{
    /// <summary>
    /// Çevrimdışı DNS ve URL Filtreleme Sistemi (DnsFilterService, HostsInjectionHelper,
    /// UrlBlocklistManager ve ZoneIdentifierAnalyzer) test paketi.
    /// Hosts enjeksiyonu, URL kara liste eşleştirme, MOTW indirme analizi ve yerel sinkhole'u test eder.
    /// </summary>
    [Collection("SequentialDiskTests")]
    public class DnsFilterTest : IDisposable
    {
        private readonly string _tempDir;
        private readonly string _mockHostsFile;

        public DnsFilterTest()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "Aegis_DnsFilterTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_tempDir);
            _mockHostsFile = Path.Combine(_tempDir, "hosts");

            File.WriteAllText(_mockHostsFile, "# Standard Windows Hosts\r\n127.0.0.1 localhost\r\n::1 localhost\r\n10.0.0.1 internal.server\r\n");
        }

        [Fact]
        public void HostsInjection_AppliesSinkholeWithDelimitersAndPreservesOriginalHosts()
        {
            var helper = new HostsInjectionHelper(_mockHostsFile);

            var blockedDomains = new[]
            {
                ("c2-bad-server.biz", "C2Server"),
                ("phishing-login.com", "Phishing"),
                ("miner-pool.xyz", "CryptoMining"),
                ("ad-malware.net", "Malvertising")
            };

            // 1. Enjeksiyon
            bool success = helper.ApplySinkhole(blockedDomains, SinkholeIpMode.Loopback);
            Assert.True(success);
            Assert.True(helper.IsSinkholeActive());
            Assert.Equal(4, helper.GetSinkholeEntryCount());

            string content = File.ReadAllText(_mockHostsFile);
            Assert.Contains(HostsInjectionHelper.SinkholeMarkerBegin, content);
            Assert.Contains(HostsInjectionHelper.SinkholeMarkerEnd, content);
            Assert.Contains("127.0.0.1 c2-bad-server.biz", content);
            Assert.Contains("127.0.0.1 phishing-login.com", content);
            Assert.Contains("127.0.0.1 miner-pool.xyz", content);
            Assert.Contains("127.0.0.1 ad-malware.net", content);
            Assert.Contains("10.0.0.1 internal.server", content); // Orijinal satır korunmalı

            // 2. Sinkhole Kaldırma
            bool removed = helper.RemoveSinkhole();
            Assert.True(removed);
            Assert.False(helper.IsSinkholeActive());
            Assert.Equal(0, helper.GetSinkholeEntryCount());

            string cleaned = File.ReadAllText(_mockHostsFile);
            Assert.DoesNotContain(HostsInjectionHelper.SinkholeMarkerBegin, cleaned);
            Assert.Contains("10.0.0.1 internal.server", cleaned);

            // 3. Yedekten Geri Yükleme
            bool restored = helper.RestoreBackup();
            Assert.True(restored);
            string restoredContent = File.ReadAllText(_mockHostsFile);
            Assert.Contains("10.0.0.1 internal.server", restoredContent);
        }

        [Theory]
        [InlineData("c2-redline-stealer.biz", UrlBlockCategory.C2Server)]
        [InlineData("api.c2-redline-stealer.biz", UrlBlockCategory.C2Server)]
        [InlineData("paypa1-security-check.com", UrlBlockCategory.Phishing)]
        [InlineData("coinhive.com", UrlBlockCategory.CryptoMining)]
        [InlineData("malvertising-traffic-hub.top", UrlBlockCategory.Malvertising)]
        public void UrlBlocklist_DetectsCategorizedDomainsAndSubdomains(string query, UrlBlockCategory expectedCategory)
        {
            var manager = new UrlBlocklistManager(_tempDir);

            var verdict = manager.EvaluateUrl(query);

            Assert.True(verdict.IsBlocked, $"Query engellenmelidir: {query}");
            Assert.Equal(expectedCategory, verdict.Category);
            Assert.True(verdict.RiskScore >= 70);
        }

        [Fact]
        public void UrlBlocklist_SupportsDiverseFormats_AdblockAndRegex()
        {
            var manager = new UrlBlocklistManager(_tempDir);

            // Hosts satırı
            manager.AddRule("127.0.0.1 custom-threat.org", UrlBlockCategory.C2Server);
            // Adblock formatı
            manager.AddRule("||ad-popunder.biz^", UrlBlockCategory.Malvertising);
            // Regex URL kuralı
            manager.AddRule("regex:^https?:\\/\\/.*\\/trojan\\/download\\.php", UrlBlockCategory.C2Server);

            Assert.True(manager.EvaluateUrl("custom-threat.org").IsBlocked);
            Assert.True(manager.EvaluateUrl("sub.custom-threat.org").IsBlocked);
            Assert.True(manager.EvaluateUrl("ad-popunder.biz").IsBlocked);
            Assert.True(manager.EvaluateUrl("https://safe-domain.com/trojan/download.php?v=2").IsBlocked);
            Assert.False(manager.EvaluateUrl("https://safe-domain.com/legit/download.php").IsBlocked);
        }

        [Fact]
        public void ZoneIdentifier_DetectsInternetDownloadAndCorrelatesWithThreatFeeds()
        {
            var manager = new UrlBlocklistManager(_tempDir);
            var analyzer = new ZoneIdentifierAnalyzer(manager);

            // Temiz indirme
            string cleanIni = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://download.visualstudio.microsoft.com/setup.exe\r\nReferrerUrl=https://visualstudio.microsoft.com";
            var cleanVerdict = analyzer.ParseZoneIdentifierContent(cleanIni, "setup.exe");
            Assert.True(cleanVerdict.HasZoneIdentifier);
            Assert.True(cleanVerdict.IsFromInternet);
            Assert.False(cleanVerdict.IsBlockedOrigin);
            Assert.Equal(SecurityZone.Internet, cleanVerdict.Zone);

            // C2 Komuta Kontrol kaynağından indirilmiş zararlı dosya
            string c2Ini = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://c2-redline-stealer.biz/stealer.exe\r\nReferrerUrl=https://phishing-gate.xyz";
            var c2Verdict = analyzer.ParseZoneIdentifierContent(c2Ini, "stealer.exe");
            Assert.True(c2Verdict.HasZoneIdentifier);
            Assert.True(c2Verdict.IsBlockedOrigin);
            Assert.Equal(UrlBlockCategory.C2Server, c2Verdict.OriginCategory);
            Assert.Equal(100, c2Verdict.RiskScore);
            Assert.Contains("TEHLİKELİ İNDİRME", c2Verdict.Recommendation);
        }

        [Fact]
        public async Task DnsFilterService_ResolvesToSinkholeForBlockedDomains()
        {
            var manager = new UrlBlocklistManager(_tempDir);
            var hostsHelper = new HostsInjectionHelper(_mockHostsFile);
            using var dnsService = new DnsFilterService(manager, hostsHelper);

            var res = await dnsService.ResolveDomainAsync("c2-redline-stealer.biz", useDohIfOnline: false);

            Assert.True(res.IsBlocked);
            Assert.Equal(UrlBlockCategory.C2Server, res.BlockCategory);
            Assert.Equal("Local-Sinkhole", res.ResolutionSource);
            Assert.Contains(IPAddress.Parse("127.0.0.1"), res.ResolvedAddresses);

            var stats = dnsService.GetStatistics();
            Assert.True(stats.BlockedQueriesCount >= 1);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempDir))
                {
                    Directory.Delete(_tempDir, recursive: true);
                }
            }
            catch { }
        }
    }
}
