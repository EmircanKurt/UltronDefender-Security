using System;
using System.ComponentModel;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert coordinator lifecycle fixtures; no live scanner, service, quarantine or process action is invoked.</summary>
public sealed class ScanCoordinatorFailureTests
{
    /// <summary>A scanner fault produces one failed result with safe typed diagnostics and leaves the coordinator retryable.</summary>
    [Fact]
    public async Task ThrowingScanner_ReportsOneFailureAndAllowsRetry()
    {
        var scanner = new FixtureScanner((_, _) => throw new Win32Exception(5, @"Private C:\User\secret.dat"));
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        Guid sessionId = Guid.Empty;
        int finalNotifications = 0;
        ScanResult? observed = null;
        coordinator.ScanSessionStarted += session => sessionId = session.SessionId;
        coordinator.ScanCompleted += result => { finalNotifications++; observed = result; };

        var result = Assert.IsType<ScanResult>(await coordinator.StartScanAsync(ScanType.Custom, "fixture"));

        Assert.Same(result, observed);
        Assert.Equal(1, finalNotifications);
        Assert.Equal(ScanStatus.Failed, result.Status);
        Assert.Equal(ScanState.Failed, coordinator.State);
        Assert.Equal(ScanStopReason.Error, coordinator.StopReason);
        Assert.Null(coordinator.CurrentSession);
        Assert.False(coordinator.IsScanning);
        Assert.NotEqual(100, coordinator.ProgressPercent);
        var failure = Assert.IsType<ScanFailureInfo>(result.FailureInfo);
        Assert.Equal(ScanFailureReason.UnexpectedException, failure.Reason);
        Assert.Equal(5, failure.NativeErrorCode);
        Assert.NotNull(failure.HResult);
        Assert.Equal(sessionId, failure.CorrelationId);
        Assert.Equal(DateTimeKind.Utc, failure.OccurredAtUtc.Kind);
        Assert.DoesNotContain("secret", failure.SafeMessage, StringComparison.OrdinalIgnoreCase);

        scanner.Run = (_, _) => Task.FromResult(new ScanResult { Status = ScanStatus.Completed });
        var retry = await coordinator.StartScanAsync(ScanType.Custom, "fixture");
        Assert.Equal(ScanStatus.Completed, retry?.Status);
        Assert.Equal(2, finalNotifications);
        Assert.Equal(2, scanner.StartCount);
    }

    /// <summary>An explicit failed scanner result keeps its findings, counters and coverage instead of becoming completed.</summary>
    [Fact]
    public async Task ReturnedFailedResult_PreservesAllObservations()
    {
        var finding = new SecurityFinding { Title = "Synthetic observation", RiskScore = 10 };
        var expected = new ScanResult
        {
            Status = ScanStatus.Failed, TotalFiles = 23, ScannedFiles = 7, SkippedFiles = 2,
            FailedFiles = 3, TimedOutFiles = 1, ElapsedMs = 400, Findings = [finding]
        };
        expected.Coverage.RecordDirectoryError();
        expected.Coverage.RecordPartialArchive();
        var coordinator = new ScanCoordinatorService(new FixtureScanner((_, _) => Task.FromResult(expected)), new SecurityFindingService());
        int notifications = 0;
        coordinator.ScanCompleted += _ => notifications++;

        var result = await coordinator.StartScanAsync(ScanType.Custom);

        Assert.Same(expected, result);
        Assert.Equal(ScanStatus.Failed, result?.Status);
        Assert.Equal(ScanFailureReason.ScannerReportedFailure, result?.FailureInfo?.Reason);
        Assert.Equal(23, result?.TotalFiles);
        Assert.Equal(7, result?.ScannedFiles);
        Assert.Equal(2, result?.SkippedFiles);
        Assert.Equal(3, result?.FailedFiles);
        Assert.Equal(1, result?.TimedOutFiles);
        Assert.Equal(400, result?.ElapsedMs);
        Assert.Equal(1, result?.Coverage.UnreadableDirectories);
        Assert.Equal(1, result?.Coverage.PartialArchives);
        Assert.Same(finding, Assert.Single(coordinator.CurrentFindings));
        Assert.Equal(1, notifications);
    }

    /// <summary>A scanner's null or running result is a typed terminal failure, never a successful empty scan.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MissingOrNonterminalResult_IsFailed(bool returnNull)
    {
        var scanner = new FixtureScanner((_, _) => Task.FromResult(returnNull ? null! : new ScanResult { Status = ScanStatus.Running }));
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        int notifications = 0;
        coordinator.ScanCompleted += _ => notifications++;
        var result = await coordinator.StartScanAsync(ScanType.Custom);
        Assert.Equal(ScanStatus.Failed, result?.Status);
        Assert.Equal(returnNull ? ScanFailureReason.MissingResult : ScanFailureReason.InvalidResultStatus, result?.FailureInfo?.Reason);
        Assert.Equal(1, notifications);
        Assert.Equal(ScanState.Failed, coordinator.State);
    }

    /// <summary>A foreign cancellation or closed channel cannot claim user cancellation while the owning token is active.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ForeignCancellationOrChannelClosure_IsFailed(bool cancellation)
    {
        var scanner = new FixtureScanner((progress, _) =>
        {
            progress?.Report(new ScanProgress { TotalFiles = 19, ScannedFiles = 8, SkippedFiles = 2, FailedFiles = 3, TimedOutFiles = 1 });
            return Task.FromException<ScanResult>(cancellation ? new OperationCanceledException("Fixture foreign token") : new ChannelClosedException());
        });
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        var result = await coordinator.StartScanAsync(ScanType.Custom);
        Assert.Equal(ScanStatus.Failed, result?.Status);
        Assert.Equal(cancellation ? ScanFailureReason.UnexpectedCancellation : ScanFailureReason.ChannelClosed, result?.FailureInfo?.Reason);
        Assert.Equal(19, result?.TotalFiles);
        Assert.Equal(8, result?.ScannedFiles);
        Assert.Equal(2, result?.SkippedFiles);
        Assert.Equal(3, result?.FailedFiles);
        Assert.Equal(1, result?.TimedOutFiles);
        Assert.Equal(ScanStopReason.Error, coordinator.StopReason);
    }

    /// <summary>Cancellation of the owning token keeps partial counters and publishes one cancelled result.</summary>
    [Fact]
    public async Task OwnedCancellation_IsCancelledAndPreservesCounters()
    {
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var scanner = new FixtureScanner(async (progress, token) =>
        {
            progress?.Report(new ScanProgress { TotalFiles = 11, ScannedFiles = 4, SkippedFiles = 2, FailedFiles = 1, TimedOutFiles = 3 });
            started.TrySetResult(true);
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return new ScanResult { Status = ScanStatus.Completed };
        });
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        int notifications = 0;
        coordinator.ScanCompleted += _ => notifications++;
        using var cts = new CancellationTokenSource();
        var scan = coordinator.TryStartBackgroundScanAsync(ScanType.Custom, cts.Token);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cts.Cancel();
        var result = await scan.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(ScanStatus.Cancelled, result?.Status);
        Assert.Null(result?.FailureInfo);
        Assert.Equal(11, result?.TotalFiles);
        Assert.Equal(4, result?.ScannedFiles);
        Assert.Equal(2, result?.SkippedFiles);
        Assert.Equal(1, result?.FailedFiles);
        Assert.Equal(3, result?.TimedOutFiles);
        Assert.Equal(1, notifications);
        Assert.Null(coordinator.CurrentSession);
    }

    /// <summary>Throwing observers cannot stop later observers, change a successful scan, or strand its owner.</summary>
    [Fact]
    public async Task ThrowingObservers_AreIsolatedIndividually()
    {
        var scanner = new FixtureScanner((progress, _) =>
        {
            progress?.Report(new ScanProgress { ScannedFiles = 2 });
            return Task.FromResult(new ScanResult { Status = ScanStatus.Completed, ScannedFiles = 2 });
        });
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        int started = 0, progressEvents = 0, completed = 0;
        coordinator.ScanSessionStarted += _ => throw new InvalidOperationException("Fixture start observer");
        coordinator.ScanSessionStarted += _ => started++;
        coordinator.ProgressChanged += _ => throw new InvalidOperationException("Fixture progress observer");
        coordinator.ProgressChanged += _ => progressEvents++;
        coordinator.ScanCompleted += _ => throw new InvalidOperationException("Fixture report observer");
        coordinator.ScanCompleted += _ => completed++;

        var result = await coordinator.StartScanAsync(ScanType.Custom);

        Assert.Equal(ScanStatus.Completed, result?.Status);
        Assert.Null(result?.FailureInfo);
        Assert.Equal(1, started);
        Assert.Equal(1, progressEvents);
        Assert.Equal(1, completed);
        Assert.Equal(ScanState.Completed, coordinator.State);
        Assert.Null(coordinator.CurrentSession);
    }

    /// <summary>A setup callback failure publishes one failed outcome before releasing its owner for a retry.</summary>
    [Fact]
    public async Task SetupFailure_IsReportedWithoutStartingScanner()
    {
        var scanner = new FixtureScanner((_, _) => Task.FromResult(new ScanResult { Status = ScanStatus.Completed }));
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        int notifications = 0;
        coordinator.ScanCompleted += _ => notifications++;
        var result = await coordinator.TryStartManualScanAsync(ScanType.Custom, "fixture",
            () => throw new InvalidOperationException("Fixture resource configuration"));
        Assert.Equal(ScanStatus.Failed, result?.Status);
        Assert.Equal(ScanFailureStage.Preparation, result?.FailureInfo?.Stage);
        Assert.Equal(0, scanner.StartCount);
        Assert.Equal(1, notifications);
        Assert.Null(coordinator.CurrentSession);
    }

    /// <summary>An abandoned external owner emits one failed result and cannot overwrite its successor.</summary>
    [Fact]
    public async Task ExternalAbandonment_ReportsFailureAndReleasesOwner()
    {
        var coordinator = new ScanCoordinatorService(new FixtureScanner((_, _) => Task.FromResult(new ScanResult { Status = ScanStatus.Completed })), new SecurityFindingService());
        int notifications = 0;
        ScanResult? failed = null;
        coordinator.ScanCompleted += _ => throw new InvalidOperationException("Fixture observer");
        coordinator.ScanCompleted += result => { notifications++; failed = result; };
        var external = Assert.IsAssignableFrom<IExternalScanRegistration>(coordinator.TryRegisterExternalScanner(() => { }, () => { }, () => { }));
        external.ReportProgress(new ScanProgress { ScannedFiles = 3, FailedFiles = 2, TimedOutFiles = 1 });
        external.Dispose();
        external.Dispose();
        Assert.Equal(1, notifications);
        Assert.Equal(ScanStatus.Failed, failed?.Status);
        Assert.Equal(ScanFailureReason.ExternalScannerAbandoned, failed?.FailureInfo?.Reason);
        Assert.Equal(3, failed?.ScannedFiles);
        Assert.Equal(2, failed?.FailedFiles);
        Assert.Equal(1, failed?.TimedOutFiles);
        Assert.False(coordinator.IsExternalScanRunning);
        Assert.Equal(ScanStatus.Completed, (await coordinator.StartScanAsync(ScanType.Custom))?.Status);
        Assert.False(external.ReportProgress(new ScanProgress { ScannedFiles = 999 }));
        Assert.Equal(2, notifications);
    }

    /// <summary>Pausing cleanup failure cannot prevent cancellation of the owned token.</summary>
    [Fact]
    public async Task ResumeFailure_DoesNotPreventOwnedCancellation()
    {
        var scanner = new FixtureScanner(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return new ScanResult { Status = ScanStatus.Completed };
        }) { FailResume = true };
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        var scan = coordinator.StartScanAsync(ScanType.Custom);
        coordinator.PauseScan();
        coordinator.CancelScan();
        var result = await scan.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(ScanStatus.Cancelled, result?.Status);
        Assert.Null(coordinator.CurrentSession);
        Assert.Equal(ScanState.Cancelled, coordinator.State);
    }

    /// <summary>An independent scanner failure does not become user cancellation merely because cancellation also occurred.</summary>
    [Fact]
    public async Task FaultDuringCancellation_RemainsFailed()
    {
        using var cancellation = new CancellationTokenSource();
        var scanner = new FixtureScanner((_, _) =>
        {
            cancellation.Cancel();
            return Task.FromException<ScanResult>(new InvalidOperationException("Independent scanner fault"));
        });
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        var result = await coordinator.TryStartBackgroundScanAsync(ScanType.Custom, cancellation.Token);
        Assert.Equal(ScanStatus.Failed, result?.Status);
        Assert.Equal(ScanFailureReason.UnexpectedException, result?.FailureInfo?.Reason);
    }

    private sealed class FixtureScanner(Func<IProgress<ScanProgress>?, CancellationToken, Task<ScanResult>> run) : IFileScanner
    {
        internal Func<IProgress<ScanProgress>?, CancellationToken, Task<ScanResult>> Run { get; set; } = run;
        internal int StartCount { get; private set; }
        internal bool FailResume { get; set; }
        public bool IsPaused { get; private set; }
        public void PauseScan() => IsPaused = true;
        public void ResumeScan() { if (FailResume) throw new InvalidOperationException("Fixture resume failure"); IsPaused = false; }
        public Task<SecurityFinding?> ScanFileAsync(string path, CancellationToken cancellationToken = default) => Task.FromResult<SecurityFinding?>(null);
        public Task<FileScanDetailedResult> ScanFileDetailedAsync(string path, TimeSpan perFileTimeout, CancellationToken cancellationToken = default) =>
            Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero));
        public Task<ScanResult> ScanDirectoryAsync(string path, ScanType scanType, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
        { StartCount++; return Run(progress, cancellationToken); }
    }
}
