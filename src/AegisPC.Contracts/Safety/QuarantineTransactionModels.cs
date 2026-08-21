using System;
using System.Collections.Generic;

namespace AegisPC.Contracts.Safety
{
    public class QuarantineRequest
    {
        public string TargetFilePath { get; set; } = string.Empty;
        public string ThreatReason { get; set; } = "Genel Tehdit";
        public bool ForceKillHoldingProcesses { get; set; } = true;
        public bool WipeOriginalPayloadBytes { get; set; } = true;
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
        public int QuarantineId { get; set; }
        public string RestoredPath { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }
}
