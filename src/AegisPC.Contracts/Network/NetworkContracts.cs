using System;
using System.Collections.Generic;
using AegisPC.Contracts.Detection;

namespace AegisPC.Contracts.Network
{
    public enum NetworkFlowDirection
    {
        Inbound = 1,
        Outbound = 2
    }

    public enum TransportProtocol
    {
        Tcp = 6,
        Udp = 17,
        Icmp = 1,
        Other = 0
    }

    public class NetworkFlowEvent
    {
        public string EventId { get; set; } = Guid.NewGuid().ToString("N");
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ExecutablePath { get; set; } = string.Empty;
        public NetworkFlowDirection Direction { get; set; } = NetworkFlowDirection.Outbound;
        public TransportProtocol Protocol { get; set; } = TransportProtocol.Tcp;
        public string LocalAddress { get; set; } = "127.0.0.1";
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public string? DestinationDomain { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    }

    public class NetworkConnectionVerdict
    {
        public bool IsSuspicious { get; set; }
        public bool IsC2Beaconing { get; set; }
        public int RiskScore { get; set; }
        public string ThreatTitle { get; set; } = string.Empty;
        public string ThreatCategory { get; set; } = "NetworkC2";
        public List<SecurityEvidence> Evidences { get; set; } = new();
        public string Explanation { get; set; } = string.Empty;

        public override string ToString() => $"[NetVerdict: Suspicious={IsSuspicious}, Beaconing={IsC2Beaconing}, Score={RiskScore}] {ThreatTitle}";
    }

    public interface IWfpTelemetryEngine
    {
        event Action<NetworkFlowEvent>? OnFlowRecorded;
        void IngestNetworkFlow(NetworkFlowEvent flow);
    }

    public interface INetworkProcessCorrelator
    {
        NetworkConnectionVerdict CorrelateFlow(NetworkFlowEvent flow);
        IReadOnlyList<NetworkFlowEvent> GetProcessFlowHistory(int pid, TimeSpan window);
    }
}
