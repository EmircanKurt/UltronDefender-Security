using System.Collections.Generic;
using AegisPC.Contracts.Detection;

namespace AegisPC.Contracts.AntiEvasion
{
    public class MemoryScanVerdict
    {
        public bool IsMaliciousMemoryFound { get; set; }
        public double Confidence { get; set; }
        public int SeverityScore { get; set; }
        public string ThreatTitle { get; set; } = string.Empty;
        public string ThreatCategory { get; set; } = string.Empty;
        public string MatchedPattern { get; set; } = string.Empty;
        public ulong MemoryAddress { get; set; }
        public long MemorySize { get; set; }
        public List<SecurityEvidence> Evidences { get; set; } = new();

        public override string ToString() => $"[MemoryVerdict: Malicious={IsMaliciousMemoryFound}, Score={SeverityScore}] {ThreatTitle}";
    }
}
