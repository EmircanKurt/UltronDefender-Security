using System;
using System.Collections.Generic;
using AegisPC.Contracts.Detection;

namespace AegisPC.Contracts.Behavior
{
    /// <summary>
    /// Zamansal ve çok aşamalı saldırı zinciri (MITRE ATT&CK Chain) korelasyon sonucu.
    /// </summary>
    public class AttackChainCorrelationResult
    {
        public int RootPid { get; set; }
        public string RootProcessName { get; set; } = string.Empty;
        public string RootExecutablePath { get; set; } = string.Empty;
        public int TotalRiskScore { get; set; }
        public bool IsConfirmedAttack { get; set; }
        public List<string> MitreTactics { get; set; } = new();
        public List<string> MatchedSequence { get; set; } = new();
        public List<SecurityEvidence> Evidences { get; set; } = new();
        public string ThreatTitle { get; set; } = string.Empty;
        public string Explanation { get; set; } = string.Empty;
        public DateTime FirstEventUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastEventUtc { get; set; } = DateTime.UtcNow;

        public override string ToString() => $"[AttackChain: Score {TotalRiskScore}, Confirmed: {IsConfirmedAttack}] {ThreatTitle} ({MitreTactics.Count} Tactics)";
    }
}
