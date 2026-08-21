using System;
using System.Threading.Tasks;
using AegisPC.Contracts.Network;
using AegisPC.Security.Network;
using Xunit;

namespace AegisPC.Tests
{
    public class NetworkProcessCorrelatorTests
    {
        [Fact]
        public void Test_NetworkProcessCorrelator_DetectsLolbinExternalConnection()
        {
            var correlator = new NetworkProcessCorrelator();

            var flow = new NetworkFlowEvent
            {
                ProcessId = 4444,
                ProcessName = "powershell.exe",
                RemoteAddress = "185.220.101.5",
                RemotePort = 443,
                Direction = NetworkFlowDirection.Outbound
            };

            var verdict = correlator.CorrelateFlow(flow);

            Assert.True(verdict.IsSuspicious);
            Assert.True(verdict.RiskScore >= 45);
            Assert.Contains(verdict.Evidences, e => e.RuleName == "NET_LOLBIN_OUTBOUND_C2");
        }

        [Fact]
        public void Test_NetworkProcessCorrelator_DetectsC2Beaconing()
        {
            var correlator = new NetworkProcessCorrelator();
            int pid = 8888;
            string remoteIp = "91.215.85.12";

            // Ingest 5 periodic requests exactly 5.0 seconds apart
            var baseTime = DateTime.UtcNow.AddSeconds(-25);
            for (int i = 0; i < 5; i++)
            {
                correlator.IngestNetworkFlow(new NetworkFlowEvent
                {
                    ProcessId = pid,
                    ProcessName = "beacon_agent.exe",
                    RemoteAddress = remoteIp,
                    RemotePort = 8443,
                    TimestampUtc = baseTime.AddSeconds(i * 5)
                });
            }

            var latestFlow = new NetworkFlowEvent
            {
                ProcessId = pid,
                ProcessName = "beacon_agent.exe",
                RemoteAddress = remoteIp,
                RemotePort = 8443,
                TimestampUtc = DateTime.UtcNow
            };

            var verdict = correlator.CorrelateFlow(latestFlow);

            Assert.True(verdict.IsSuspicious);
            Assert.True(verdict.IsC2Beaconing);
            Assert.True(verdict.RiskScore >= 80);
            Assert.Contains(verdict.Evidences, e => e.RuleName == "NET_C2_BEACONING_PATTERN");
        }

        [Fact]
        public void Test_NetworkProcessCorrelator_IgnoresPrivateLocalTraffic()
        {
            var correlator = new NetworkProcessCorrelator();

            var flow = new NetworkFlowEvent
            {
                ProcessId = 1234,
                ProcessName = "powershell.exe",
                RemoteAddress = "192.168.1.100",
                RemotePort = 5985
            };

            var verdict = correlator.CorrelateFlow(flow);

            Assert.False(verdict.IsSuspicious);
            Assert.Equal(0, verdict.RiskScore);
        }
    }
}
