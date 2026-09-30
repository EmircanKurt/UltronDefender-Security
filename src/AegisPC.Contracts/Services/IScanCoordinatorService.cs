using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    /// <summary>
    /// Binds an external scanner's progress, completion, and controls to its own coordinator claim.
    /// Calls made after completion or disposal are ignored rather than changing a newer scan.
    /// </summary>
    public interface IExternalScanRegistration : IDisposable
    {
        /// <summary>Reports progress only while this external scan still owns the coordinator.</summary>
        bool ReportProgress(ScanProgress progress);

        /// <summary>Completes and releases this external scan only if it still owns the coordinator.</summary>
        bool Complete(ScanResult result);
    }

    public interface IScanCoordinatorService
    {
        bool IsScanning { get; }
        ScanState State { get; }
        ScanStopReason StopReason { get; }
        ScanType CurrentScanType { get; }
        double ProgressPercent { get; }
        string CurrentFile { get; }
        int ScannedFiles { get; }
        int TotalFiles { get; }
        int FindingsCount { get; }
        string StatusText { get; }
        IReadOnlyList<SecurityFinding> CurrentFindings { get; }
        bool IsPaused { get; }
        TimeSpan ElapsedTime { get; }
        IScanSession? CurrentSession { get; }

        event Action<IScanSession>? ScanSessionStarted;
        event Action<ScanProgress>? ProgressChanged;
        event Action<ScanResult>? ScanCompleted;

        Task<ScanResult?> StartScanAsync(ScanType scanType, string customPath = "");
        /// <summary>
        /// Claims one manual scan before applying its resource policy. Implementations without
        /// ownership support fail closed rather than changing the profile of an active scan.
        /// A null result means another scan already owns the coordinator.
        /// </summary>
        Task<ScanResult?> TryStartManualScanAsync(ScanType scanType, string customPath, Action beforeOwnedScanStarts)
            => Task.FromException<ScanResult?>(new NotSupportedException("Atomic manual scan ownership is unavailable."));
        /// <summary>
        /// Atomically claims the coordinator for an external scan. Unsupported implementations
        /// return null, so an external sweep cannot race a manual session by default.
        /// </summary>
        IExternalScanRegistration? TryRegisterExternalScanner(Action pauseAction, Action resumeAction, Action cancelAction)
            => null;
        IDisposable RegisterExternalScanner(Action pauseAction, Action resumeAction, Action cancelAction);
        void RegisterExternalScanProgress(ScanProgress progress);
        void CompleteExternalScan(ScanResult result);
        void PauseScan();
        void ResumeScan();
        void CancelScan();
    }
}
