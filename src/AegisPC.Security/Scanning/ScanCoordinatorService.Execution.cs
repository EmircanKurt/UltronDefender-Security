using System;
using System.ComponentModel;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>Creates and publishes terminal outcomes without confusing scanner faults with user cancellation.</summary>
public partial class ScanCoordinatorService
{
    private sealed class OwnedScanProgress : IProgress<ScanProgress>
    {
        private readonly ScanCoordinatorService _owner;
        private readonly ScanSession _session;
        internal OwnedScanProgress(ScanCoordinatorService owner, ScanSession session)
        { _owner = owner; _session = session; }
        public void Report(ScanProgress value) => _owner.ReportOwnedProgress(_session, value);
    }

    private void ReportOwnedProgress(ScanSession session, ScanProgress progress)
    {
        lock (_lock)
        {
            if (_currentSession != session || !session.IsActive) return;
            ProgressPercent = progress.ProgressPercent;
            CurrentFile = progress.CurrentFile;
            ScannedFiles = progress.ScannedFiles;
            TotalFiles = progress.TotalFiles;
            ElapsedTime = progress.ElapsedTime;
            session.LatestProgress = progress;
            if (_state == ScanState.Scanning)
                StatusText = $"{CurrentScanType} taraması: {progress.ScannedFiles:N0} dosya incelendi";
        }
        NotifyObservers(ProgressChanged, progress, nameof(ProgressChanged));
    }

    private async Task CompleteOwnedScanAsync(ScanSession session, TaskCompletionSource<ScanResult?> completion)
    {
        ScanResult result;
        try { result = await RunOwnedScanAsync(session); }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Owned scan {ScanId} failed outside scanner execution.", session.SessionId);
            result = CreateInterruptedResult(session, ScanStatus.Failed);
            result.FailureInfo = CreateFailure(session.SessionId, ScanFailureStage.Scanning, ex);
        }
        PublishOwnedOutcome(session, result);
        completion.TrySetResult(result);
    }

    private async Task<ScanResult> RunOwnedScanAsync(ScanSession session)
    {
        ScanResult? result = null;
        var stage = ScanFailureStage.Scanning;
        try
        {
            _logger?.LogInformation("Starting {ScanType} scan {ScanId}.", session.ScanType, session.SessionId);
            result = await _fileScanner.ScanDirectoryAsync(session.CustomPath, session.ScanType,
                new OwnedScanProgress(this, session), session.CancellationToken);
            if (result == null)
            {
                result = CreateInterruptedResult(session, ScanStatus.Failed);
                result.FailureInfo = CreateFailure(session.SessionId, stage, reason: ScanFailureReason.MissingResult);
            }
            NormalizeResult(result, session.SessionId, session.StartedAtUtc, session.ScanType, session.CustomPath);
            if (result.Status is ScanStatus.Failed or ScanStatus.Cancelled) return result;
            session.CancellationToken.ThrowIfCancellationRequested();
            stage = ScanFailureStage.PolicyEnforcement;
            await ApplyFindingPolicyAsync(result, session.CancellationToken);
            session.CancellationToken.ThrowIfCancellationRequested();
            return result;
        }
        catch (Exception ex)
        {
            if (ex is ScanExecutionFailureException scannerFailure) result = scannerFailure.PartialResult;
            result ??= CreateInterruptedResult(session, ScanStatus.Failed);
            if (session.CancellationToken.IsCancellationRequested && ex is OperationCanceledException cancelled &&
                (cancelled.CancellationToken == session.CancellationToken || cancelled.CancellationToken == default))
                result.Status = ScanStatus.Cancelled;
            else
            {
                result.Status = ScanStatus.Failed;
                result.FailureInfo ??= CreateFailure(session.SessionId, stage, ex);
                _logger?.LogError(ex, "Scan {ScanId} ended with a failure at {FailureStage}.", session.SessionId, stage);
            }
            if (result.Status == ScanStatus.Cancelled) result.FailureInfo = null;
            MergeInterruptedCounters(result, session.LatestProgress);
            result.Coverage.RecordLimitation(result.Status == ScanStatus.Cancelled
                ? "ScanCancelledBeforeCompletion" : "ScannerTerminatedBeforeResult");
            NormalizeResult(result, session.SessionId, session.StartedAtUtc, session.ScanType, session.CustomPath);
            return result;
        }
    }

    private ScanResult CreateInterruptedResult(ScanSession session, ScanStatus status)
    {
        var result = new ScanResult
        {
            ScanType = session.ScanType,
            CustomPath = session.CustomPath,
            StartedAt = session.StartedAtUtc,
            CompletedAt = DateTime.UtcNow,
            Status = status,
            ElapsedMs = (long)Math.Max(0, (DateTime.UtcNow - session.StartedAtUtc).TotalMilliseconds)
        };
        MergeInterruptedCounters(result, session.LatestProgress);
        result.Coverage.RecordLimitation(status == ScanStatus.Cancelled
            ? "ScanCancelledBeforeCompletion" : "ScannerTerminatedBeforeResult");
        return result;
    }

    private static void MergeInterruptedCounters(ScanResult result, ScanProgress? progress)
    {
        if (progress == null) return;
        result.TotalFiles = Math.Max(result.TotalFiles, progress.TotalFiles);
        result.ScannedFiles = Math.Max(result.ScannedFiles, progress.ScannedFiles);
        result.SkippedFiles = Math.Max(result.SkippedFiles, progress.SkippedFiles);
        result.FailedFiles = Math.Max(result.FailedFiles, progress.FailedFiles);
        result.TimedOutFiles = Math.Max(result.TimedOutFiles, progress.TimedOutFiles);
        result.ElapsedMs = Math.Max(result.ElapsedMs, (long)progress.ElapsedTime.TotalMilliseconds);
    }

    private static ScanFailureInfo CreateFailure(Guid correlationId, ScanFailureStage stage,
        Exception? exception = null, ScanFailureReason? reason = null)
    {
        if (exception is ScanExecutionFailureException { InnerException: { } inner }) exception = inner;
        var cause = reason ?? (exception switch
        {
            OperationCanceledException => ScanFailureReason.UnexpectedCancellation,
            ChannelClosedException => ScanFailureReason.ChannelClosed,
            _ => ScanFailureReason.UnexpectedException
        });
        return new ScanFailureInfo
        {
            Stage = stage,
            Reason = cause,
            HResult = exception?.HResult,
            NativeErrorCode = (exception as Win32Exception)?.NativeErrorCode,
            SafeMessage = cause switch
            {
                ScanFailureReason.MissingResult => "The scanner did not return an inspection result.",
                ScanFailureReason.ScannerReportedFailure => "The scanner reported that inspection failed.",
                ScanFailureReason.UnexpectedCancellation => "An inspection operation cancelled before the scan was cancelled.",
                ScanFailureReason.ChannelClosed => "The inspection channel closed unexpectedly.",
                ScanFailureReason.InvalidResultStatus => "The scanner did not return a terminal lifecycle status.",
                ScanFailureReason.ExternalScannerAbandoned => "The external scanner ended without reporting an outcome.",
                _ => "The scan could not finish the requested operation."
            },
            OccurredAtUtc = DateTime.UtcNow,
            CorrelationId = correlationId,
            IsRetryable = cause is not (ScanFailureReason.MissingResult or ScanFailureReason.InvalidResultStatus)
        };
    }

    private static void NormalizeResult(ScanResult result, Guid correlationId, DateTime startedAt,
        ScanType scanType, string customPath)
    {
        result.ScanType = scanType;
        result.CustomPath ??= customPath;
        if (result.StartedAt == default) result.StartedAt = startedAt;
        result.CompletedAt ??= DateTime.UtcNow;
        result.Findings ??= new();
        result.Coverage ??= new();
        if (result.Status is not (ScanStatus.Completed or ScanStatus.Cancelled or ScanStatus.Failed))
        {
            result.Status = ScanStatus.Failed;
            result.FailureInfo ??= CreateFailure(correlationId, ScanFailureStage.Scanning,
                reason: ScanFailureReason.InvalidResultStatus);
        }
        if (result.Status == ScanStatus.Failed)
        {
            result.FailureInfo ??= CreateFailure(correlationId, ScanFailureStage.Scanning,
                reason: ScanFailureReason.ScannerReportedFailure);
            result.Coverage.RecordLimitation("ScanFailedBeforeCompletion");
        }
        else if (result.Status == ScanStatus.Cancelled)
            result.Coverage.RecordLimitation("ScanCancelledBeforeCompletion");
    }

    private void PublishOwnedOutcome(ScanSession session, ScanResult result)
    {
        lock (_lock)
        {
            if (!ReferenceEquals(_currentSession, session)) return;
            session.MarkEnded();
            ApplyTerminalDisplay(result);
            ResumeScannerForCleanup();
        }
        try { NotifyObservers(ScanCompleted, result, nameof(ScanCompleted)); }
        finally
        {
            lock (_lock)
            {
                if (ReferenceEquals(_currentSession, session))
                {
                    _currentSession = null;
                    _activeScanTask = null;
                    _scanCts?.Dispose();
                    _scanCts = null;
                }
            }
        }
    }

    private void ApplyTerminalDisplay(ScanResult result)
    {
        ScannedFiles = result.ScannedFiles;
        TotalFiles = result.TotalFiles;
        ElapsedTime = TimeSpan.FromMilliseconds(Math.Max(0, result.ElapsedMs));
        _currentFindings.Clear();
        _currentFindings.AddRange(result.Findings);
        if (result.Status == ScanStatus.Failed)
        {
            _state = ScanState.Failed;
            _stopReason = ScanStopReason.Error;
            ProgressPercent = Math.Min(ProgressPercent, 99);
            StatusText = "Tarama tamamlanamadı. Ayrıntılar tarama raporunda.";
            CurrentFile = "Hata oluştu.";
        }
        else if (result.Status == ScanStatus.Cancelled)
        {
            _state = ScanState.Cancelled;
            _stopReason = ScanStopReason.UserCancelled;
            ProgressPercent = Math.Min(ProgressPercent, 99);
            StatusText = "Tarama durduruldu.";
            CurrentFile = "İptal edildi.";
        }
        else
        {
            _state = ScanState.Completed;
            _stopReason = ScanStopReason.CompletedNormally;
            ProgressPercent = 100;
            StatusText = $"Tarama tamamlandı. {result.ScannedFiles:N0} dosya incelendi, {_currentFindings.Count} riskli bulgu.";
            CurrentFile = "Tarama tamamlandı.";
        }
    }

    private void ResumeScannerForCleanup()
    {
        try { if (_fileScanner.IsPaused) _fileScanner.ResumeScan(); }
        catch (Exception ex) { _logger?.LogWarning(ex, "Failed to resume the scanner during owned cleanup."); }
    }
}
