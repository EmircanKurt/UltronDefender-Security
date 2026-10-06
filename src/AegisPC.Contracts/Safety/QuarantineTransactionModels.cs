using System;
using System.Collections.Generic;

namespace AegisPC.Contracts.Safety
{
    /// <summary>
    /// Identifies a caller's claimed detector decision for the exact content being contained.
    /// The vault independently checks its known-malware hash database; other claims cannot
    /// raise the persisted risk tier until an independent verifier exists.
    /// </summary>
    public enum QuarantineDetectionEvidenceKind
    {
        None = 0,
        Heuristic = 1,
        VerifiedKnownMaliciousHash = 2,
        VerifiedContentSignature = 3
    }

    /// <summary>
    /// Carries a structured detector claim and its content identity. This is not an authorization
    /// token; the vault must independently verify the claimed detection before raising risk.
    /// </summary>
    public sealed class QuarantineDetectionEvidence
    {
        /// <summary>The claimed detector decision, or None when no conclusion is available.</summary>
        public QuarantineDetectionEvidenceKind Kind { get; init; }

        /// <summary>SHA-256 of the exact content inspected by the detector.</summary>
        public string? ContentSha256 { get; init; }
    }

    /// <summary>Requests containment; the display reason never establishes maliciousness.</summary>
    public class QuarantineRequest
    {
        public string TargetFilePath { get; set; } = string.Empty;
        /// <summary>Human-readable explanation only; it must not affect the recorded risk tier.</summary>
        public string ThreatReason { get; set; } = "Genel Tehdit";
        public bool ForceKillHoldingProcesses { get; set; } = true;
        public bool WipeOriginalPayloadBytes { get; set; } = true;
        /// <summary>Optional detected SHA-256; containment must not delete different content or kill holders.</summary>
        public string? ExpectedSha256 { get; set; }

        /// <summary>
        /// Optional detector claim bound to a SHA-256. The vault independently checks known
        /// malicious hashes; unsupported or mismatched caller claims cannot raise risk.
        /// </summary>
        public QuarantineDetectionEvidence? DetectionEvidence { get; set; }
    }

    public enum QuarantineTransactionStatus
    {
        NotStarted,
        PreFlightPassed,
        ProcessesTerminated,
        VaultStagingCompleted,
        OriginalFileRemoved,
        Committed,
        AbortedProtectedPath,
        AbortedReparsePointTrap,
        AbortedFileInaccessible,
        AbortedEncryptionFailed,
        RolledBack
    }

    public class QuarantineTransactionResult
    {
        /// <summary>True when an existing verified recovery copy satisfied this operation; no new quarantine notification should be emitted.</summary>
        public bool WasAlreadyQuarantined { get; set; }
        public bool Success { get; set; }
        public int QuarantineId { get; set; }
        public string OriginalPath { get; set; } = string.Empty;
        public string CanonicalPath { get; set; } = string.Empty;
        public string VaultContainerPath { get; set; } = string.Empty;
        public string SHA256 { get; set; } = string.Empty;
        public QuarantineTransactionStatus Status { get; set; }
        public string Message { get; set; } = string.Empty;
        public List<string> AuditSteps { get; set; } = new();
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

        public override string ToString() => $"[Quarantine: {Success}, ID: {QuarantineId}, Status: {Status}] {Message}";
    }

    public class QuarantineRestoreResult
    {
        public bool Success { get; set; }
        /// <summary>True when destination publication succeeded but persistent metadata still requires reconciliation.</summary>
        public bool AuditPending { get; set; }
        public int QuarantineId { get; set; }
        public string RestoredPath { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }
}
