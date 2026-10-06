using System;
using System.Threading;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Maintains external scanner ownership and a single terminal result, including abandoned registrations.</summary>
public partial class ScanCoordinatorService
{
    private sealed class ExternalScannerSubscription : IExternalScanRegistration
    {
        private readonly ScanCoordinatorService _owner;
        private int _ended;
        internal ExternalScannerSubscription(ScanCoordinatorService owner) { _owner = owner; }
        internal Guid CorrelationId { get; } = Guid.NewGuid();
        internal DateTime StartedAtUtc { get; } = DateTime.UtcNow;
        internal ScanProgress? LatestProgress { get; set; }
        internal bool IsEnded => Volatile.Read(ref _ended) != 0;
        public bool ReportProgress(ScanProgress progress) =>
            !IsEnded && _owner.TryReportExternalProgress(this, progress);
        public bool Complete(ScanResult result) => Interlocked.Exchange(ref _ended, 1) == 0 &&
            _owner.TryCompleteExternalScan(this, result);
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _ended, 1) == 0) _owner.ReleaseExternalScanner(this);
        }
    }

    /// <summary>Claims an external scan slot, or returns null while any scan owns the coordinator.</summary>
    public IExternalScanRegistration? TryRegisterExternalScanner(Action pauseAction, Action resumeAction, Action cancelAction)
    {
        ArgumentNullException.ThrowIfNull(pauseAction);
        ArgumentNullException.ThrowIfNull(resumeAction);
        ArgumentNullException.ThrowIfNull(cancelAction);
        lock (_lock)
        {
            if (_externalRegistration != null || _currentSession != null ||
                (_activeScanTask != null && !_activeScanTask.IsCompleted)) return null;
            var registration = new ExternalScannerSubscription(this);
            _externalRegistration = registration;
            _isExternalScanRunning = true;
            _externalPauseAction = pauseAction;
            _externalResumeAction = resumeAction;
            _externalCancelAction = cancelAction;
            ResetScanDisplay(ScanType.Quick, "Başlangıç taraması hazırlanıyor...", "Başlangıç güvenlik taraması hazırlanıyor...");
            return registration;
        }
    }

    /// <summary>Claims the legacy external slot in this asynchronous context; a busy coordinator throws.</summary>
    public IDisposable RegisterExternalScanner(Action pauseAction, Action resumeAction, Action cancelAction)
    {
        var registration = TryRegisterExternalScanner(pauseAction, resumeAction, cancelAction)
            as ExternalScannerSubscription ?? throw new InvalidOperationException("A scan already owns the coordinator.");
        _legacyExternalRegistration.Value = registration;
        return registration;
    }

    /// <summary>Accepts progress only from this asynchronous context's current legacy external owner.</summary>
    public void RegisterExternalScanProgress(ScanProgress progress) => _legacyExternalRegistration.Value?.ReportProgress(progress);

    /// <summary>Completes this asynchronous context's current legacy external owner once.</summary>
    public void CompleteExternalScan(ScanResult result) => _legacyExternalRegistration.Value?.Complete(result);

    private bool TryReportExternalProgress(ExternalScannerSubscription registration, ScanProgress progress)
    {
        ArgumentNullException.ThrowIfNull(progress);
        lock (_lock)
        {
            if (!ReferenceEquals(_externalRegistration, registration) || registration.IsEnded ||
                _state is not (ScanState.Scanning or ScanState.Paused or ScanState.Cancelling)) return false;
            registration.LatestProgress = progress;
            CurrentScanType = progress.ScanType;
            ProgressPercent = progress.ProgressPercent;
            CurrentFile = progress.CurrentFile;
            ScannedFiles = progress.ScannedFiles;
            TotalFiles = progress.TotalFiles;
            ElapsedTime = progress.ElapsedTime;
            if (_state == ScanState.Scanning)
                StatusText = $"Arka plan başlangıç taraması: {progress.ScannedFiles:N0} dosya incelendi (%{(int)progress.ProgressPercent})";
        }
        NotifyObservers(ProgressChanged, progress, nameof(ProgressChanged));
        return true;
    }

    private void ReleaseExternalScanner(ExternalScannerSubscription registration)
    {
        ScanResult result;
        lock (_lock)
        {
            if (!ReferenceEquals(_externalRegistration, registration)) return;
            result = CreateExternalInterruptedResult(registration, _state == ScanState.Cancelling
                ? ScanStatus.Cancelled : ScanStatus.Failed);
            if (result.Status == ScanStatus.Failed)
                result.FailureInfo = CreateFailure(registration.CorrelationId, ScanFailureStage.ExternalScanner,
                    reason: ScanFailureReason.ExternalScannerAbandoned);
        }
        TryCompleteExternalScan(registration, result);
    }

    private ScanResult CreateExternalInterruptedResult(ExternalScannerSubscription registration, ScanStatus status)
    {
        var result = new ScanResult
        {
            ScanType = CurrentScanType,
            StartedAt = registration.StartedAtUtc,
            CompletedAt = DateTime.UtcNow,
            Status = status,
            ElapsedMs = (long)Math.Max(0, (DateTime.UtcNow - registration.StartedAtUtc).TotalMilliseconds)
        };
        MergeInterruptedCounters(result, registration.LatestProgress);
        result.Coverage.RecordLimitation("ExternalScannerEndedBeforeResult");
        return result;
    }

    private bool TryCompleteExternalScan(ExternalScannerSubscription registration, ScanResult? result)
    {
        lock (_lock)
        {
            if (!ReferenceEquals(_externalRegistration, registration)) return false;
            if (result == null)
            {
                result = CreateExternalInterruptedResult(registration, ScanStatus.Failed);
                result.FailureInfo = CreateFailure(registration.CorrelationId, ScanFailureStage.ExternalScanner,
                    reason: ScanFailureReason.MissingResult);
            }
            NormalizeResult(result, registration.CorrelationId, registration.StartedAtUtc,
                result.ScanType, result.CustomPath ?? string.Empty);
            if (result.Status is ScanStatus.Failed or ScanStatus.Cancelled)
                MergeInterruptedCounters(result, registration.LatestProgress);
            ApplyTerminalDisplay(result);
        }
        try { NotifyObservers(ScanCompleted, result, nameof(ScanCompleted)); }
        finally
        {
            lock (_lock)
            {
                if (ReferenceEquals(_externalRegistration, registration)) ClearExternalOwnership();
            }
        }
        return true;
    }

    private void ClearExternalOwnership()
    {
        _externalRegistration = null;
        _isExternalScanRunning = false;
        _externalPauseAction = null;
        _externalResumeAction = null;
        _externalCancelAction = null;
    }
}
