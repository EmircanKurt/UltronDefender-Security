using System;
using System.Collections.Generic;

namespace AegisPC.Contracts.Detection
{
    public enum EvidenceCategory
    {
        StaticSignature,
        StaticApi,
        StaticPeStructure,
        ScriptHeuristic,
        ArchiveAnomaly,
        LocationReputation,
        EntropyAnomaly,
        BehaviorProcess,
        BehaviorMemory,
        BehaviorNetwork,
        Persistence,
        AntiEvasion,
        DigitalCertificate
    }

    public enum EvidenceConfidence
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Absolute = 4
    }

    public enum DetectionVerdict
    {
        Clean = 0,
        LowRisk = 1,
        Suspicious = 2,
        HighRisk = 3,
        ConfirmedMalicious = 4,
        Unknown = 5
    }

    public enum DetectionPolicy
    {
        Allow = 0,
        Observe = 1,
        Warn = 2,
        Block = 3,
        Quarantine = 4,
        BlockAndQuarantine = 5,
        Contain = 6
    }

    /// <summary>
    /// Explainable Evidence Model.
    /// Her tespit motoru (Detector Plugin) tarafından üretilen doğrulanabilir,
    /// puan katkısı ve güven derecesi içeren adli kanıt kaydı.
    /// </summary>
    public class SecurityEvidence
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string? CorrelationId { get; set; }
        public EvidenceCategory Category { get; set; }
        public string CorrelationGroup { get; set; } = string.Empty;
        public string Type => Category.ToString();
        public string SourceDetector { get; set; } = string.Empty;
        public string Source { get => SourceDetector; set => SourceDetector = value; }
        public string RuleName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int ScoreContribution { get; set; }
        public EvidenceConfidence Confidence { get; set; } = EvidenceConfidence.Medium;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public int? ProcessId { get; set; }
        public int? ParentProcessId { get; set; }
        public string? FilePath { get; set; }
        public string? SHA256 { get; set; }
        public Dictionary<string, string> Metadata { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        public override string ToString()
        {
            string sign = ScoreContribution >= 0 ? $"+{ScoreContribution}" : $"{ScoreContribution}";
            return $"{sign} [{Category}] {Description} (Rule: {RuleName}, Conf: {Confidence})";
        }
    }
}
