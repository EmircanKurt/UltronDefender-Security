using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;

namespace AegisPC.Contracts.Services
{
    public enum StartupSweepStatus
    {
        NotStarted,
        Preparing,
        Scanning,
        ThreatsFound,
        Clean,
        Completed,
        Failed
    }

    public class StartupSweepProgress
    {
        public StartupSweepStatus Status { get; set; } = StartupSweepStatus.Preparing;
        public int ScannedFiles { get; set; }
        public int TotalFiles { get; set; }
        public int ThreatsFound { get; set; }
        public int SuspiciousFound { get; set; }
        public int CleanFiles { get; set; }
        public int SkippedUnchanged { get; set; }
        public string CurrentFile { get; set; } = string.Empty;
        public double ProgressPercent => TotalFiles > 0 ? Math.Min(100.0, (double)ScannedFiles / TotalFiles * 100.0) : 0.0;
    }

    public class StartupSweepFinding
    {
        public string FilePath { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string SHA256 { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ModifiedAt { get; set; }
        public int RiskScore { get; set; }
        public string Verdict { get; set; } = "Clean";
        public string Action { get; set; } = "Allow";
        public List<string> Evidences { get; set; } = new();
        public string CorrelationId { get; set; } = string.Empty;
        public DateTime DetectionTime { get; set; } = DateTime.UtcNow;
        public DateTime ActionTime { get; set; } = DateTime.UtcNow;
        public bool IsQuarantined { get; set; }

        // Process Correlation
        public bool IsRunningProcess { get; set; }
        public int ProcessId { get; set; }
        public int ParentProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public DateTime? ProcessStartTime { get; set; }
    }

    public class StartupSweepResult
    {
        public StartupSweepStatus FinalStatus { get; set; } = StartupSweepStatus.Clean;
        public int TotalScanned { get; set; }
        public int CleanCount { get; set; }
        public int ThreatsCount { get; set; }
        public int SuspiciousCount { get; set; }
        public int SkippedCount { get; set; }
        public TimeSpan Duration { get; set; }
        public List<StartupSweepFinding> Findings { get; set; } = new();
    }

    public interface IStartupSecuritySweepService
    {
        StartupSweepStatus Status { get; }
        bool IsRunning { get; }
        StartupSweepResult? LastResult { get; }
        event Action<StartupSweepProgress>? OnProgressChanged;
        event Action<StartupSweepFinding>? OnThreatDiscovered;
        event Action<StartupSweepResult>? OnSweepCompleted;
        Task<StartupSweepResult> RunSweepAsync(IEnumerable<string>? customTargetDirs = null, CancellationToken cancellationToken = default);
    }
}
