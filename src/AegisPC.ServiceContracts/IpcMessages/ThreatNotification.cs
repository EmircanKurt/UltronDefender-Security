using System;
using AegisPC.Core.Enums;

namespace AegisPC.ServiceContracts.IpcMessages
{
    public class ThreatNotification
    {
        /// <summary>Legacy senders default to visible unclassified/incomplete metadata.</summary>
        public SoftwareFindingClass SoftwareClass { get; set; }
        /// <summary>Authenticated software classification.</summary>
        public AegisPC.Core.Models.SoftwareClassificationMetadata? SoftwareClassification { get; set; }
        /// <summary>Preserves content identity separately from paths.</summary>
        public string SHA256 { get; set; } = string.Empty;
        /// <summary>Stable producer rule identity; empty old values cannot authorize hiding.</summary>
        public string RuleSetVersion { get; set; } = string.Empty;
        /// <summary>Inspection completion is not implied by delivery.</summary>
        public bool InspectionComplete { get; set; }
        /// <summary>Explicit scope omissions.</summary>
        public string[] CoverageLimitations { get; set; } = [];
        /// <summary>Exclusions cannot become inspected clean content.</summary>
        public bool PolicyBypassed { get; set; }
        /// <summary>Mixed malware evidence remains visible.</summary>
        public bool HasIndependentMalwareEvidence { get; set; }
        public required string FilePath { get; set; }
        public required string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public required string ThreatName { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public required string ActionTaken { get; set; }
        public required string Details { get; set; }
        public DateTime DetectedAt { get; set; }
        /// <summary>True when this message lacks independently confirmed malware/action evidence; defaults safe for legacy senders.</summary>
        public bool IsObservationOnly { get; set; } = true;
    }
}
