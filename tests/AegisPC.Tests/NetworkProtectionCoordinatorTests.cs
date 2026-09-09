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

        [Fact]
        public void WfpEnforcementService_Lifecycle_And_BlockIp_Tracking()
        {
            using var wfp = new WfpEnforcementService();

            Assert.Equal(0, wfp.ActiveBlockFilterCount);

            bool blocked = wfp.BlockOutboundIp("198.51.100.99", "Test C2 Block");
            Assert.True(blocked);
            Assert.Equal(1, wfp.ActiveBlockFilterCount);

            bool duplicate = wfp.BlockOutboundIp("198.51.100.99", "Duplicate Block");
            Assert.True(duplicate);
            Assert.Equal(1, wfp.ActiveBlockFilterCount);

            bool unblocked = wfp.UnblockIp("198.51.100.99");
            Assert.True(unblocked);
            Assert.Equal(0, wfp.ActiveBlockFilterCount);

            // ClearDynamicFilters test
            wfp.BlockOutboundIp("198.51.100.100", "Bulk Block 1");
            wfp.BlockOutboundIp("198.51.100.101", "Bulk Block 2");
            Assert.Equal(2, wfp.ActiveBlockFilterCount);

            wfp.ClearDynamicFilters();
            Assert.Equal(0, wfp.ActiveBlockFilterCount);
        }

        [Fact]
        public void NetworkProtectionService_Integrates_WfpEnforcement_On_Malicious_Flow()
        {
            var blocklist = new UrlBlocklistManager();
            blocklist.AddRule("evil-c2.net", UrlBlockCategory.C2Server, "Test C2");
            var hostsHelper = new HostsInjectionHelper();
            var dnsFilter = new DnsFilterService(blocklist, hostsHelper);

            using var wfp = new WfpEnforcementService();
            using var service = new NetworkProtectionService(dnsFilter, wfpEnforcement: wfp);
            service.Start();

            var maliciousFlow = new NetworkFlowEvent
            {
                ProcessId = 9999,
                ProcessName = "malware.exe",
                DestinationDomain = "evil-c2.net",
                DestinationIp = "203.0.113.50",
                RemotePort = 4444
            };

            var verdict = service.AnalyzeFlow(maliciousFlow);

            Assert.NotNull(verdict);
            Assert.True(verdict.IsSuspicious);
            // Verify that WFP recorded the IP block
            Assert.True(wfp.ActiveBlockFilterCount > 0);
        }
    }
}
