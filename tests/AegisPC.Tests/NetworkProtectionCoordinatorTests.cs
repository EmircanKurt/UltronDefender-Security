using System;
using AegisPC.Contracts.Network;
using AegisPC.Service.Network;
using Xunit;

namespace AegisPC.Tests
{
    public class NetworkProtectionCoordinatorTests
    {
        [Fact]
        public void NetworkProtectionService_Lifecycle_StartsAndStopsGracefully()
        {
            var blocklist = new UrlBlocklistManager();
            var hostsHelper = new HostsInjectionHelper();
            var dnsFilter = new DnsFilterService(blocklist, hostsHelper);

            using var service = new NetworkProtectionService(dnsFilter);

            Assert.False(service.IsRunning);

            service.Start();
            Assert.True(service.IsRunning);

            var stats = service.GetStatistics();
            Assert.NotNull(stats);

            service.Stop();
            Assert.False(service.IsRunning);
        }

        [Fact]
        public void NetworkProtectionService_AnalyzeFlow_IdentifiesMaliciousDomain()
        {
            var blocklist = new UrlBlocklistManager();
            blocklist.AddRule("c2-malware-server.evil", UrlBlockCategory.C2Server, "Test");

            var hostsHelper = new HostsInjectionHelper();
            var dnsFilter = new DnsFilterService(blocklist, hostsHelper);

            using var service = new NetworkProtectionService(dnsFilter);
            service.Start();

            var maliciousFlow = new NetworkFlowEvent
            {
                ProcessId = 5566,
                ProcessName = "dropper.exe",
                DestinationDomain = "c2-malware-server.evil",
                RemoteAddress = "198.51.100.4",
                RemotePort = 443
            };

            var verdict = service.AnalyzeFlow(maliciousFlow);

            Assert.NotNull(verdict);
            Assert.True(verdict.IsSuspicious);
            Assert.True(verdict.IsC2Beaconing);
            Assert.Equal(90, verdict.RiskScore);
            Assert.Contains("c2-malware-server.evil", verdict.ThreatTitle);
        }

        [Fact]
        public void NetworkProtectionService_AnalyzeFlow_AllowsCleanTraffic()
        {
            var blocklist = new UrlBlocklistManager();
            var hostsHelper = new HostsInjectionHelper();
            var dnsFilter = new DnsFilterService(blocklist, hostsHelper);

            using var service = new NetworkProtectionService(dnsFilter);
            service.Start();

            var cleanFlow = new NetworkFlowEvent
            {
                ProcessId = 1200,
                ProcessName = "browser.exe",
                DestinationDomain = "github.com",
                RemoteAddress = "140.82.121.4",
                RemotePort = 443
            };

            var verdict = service.AnalyzeFlow(cleanFlow);

            Assert.NotNull(verdict);
            Assert.False(verdict.IsSuspicious);
            Assert.Equal(0, verdict.RiskScore);
        }
    }
}
