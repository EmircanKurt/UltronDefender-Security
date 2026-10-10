using System.Reflection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Models a progress call already past its public ended check at the external owner's terminal boundary; all dependencies are inert.</summary>
public sealed class ExternalTerminalBoundaryReviewTests
{
    /// <summary>While terminal observers retain ownership, a pending progress call cannot replace any terminal display or emit new progress.</summary>
    [Theory]
    [InlineData(ScanStatus.Completed, ScanState.Completed)]
    [InlineData(ScanStatus.Failed, ScanState.Failed)]
    [InlineData(ScanStatus.Cancelled, ScanState.Cancelled)]
    public void PendingExternalProgress_CannotOverwriteTerminalOutcome(ScanStatus status, ScanState expectedState)
    {
        var coordinator = new ScanCoordinatorService(new NoScan(), new SecurityFindingService());
        using var registration = Assert.IsAssignableFrom<IExternalScanRegistration>(
            coordinator.TryRegisterExternalScanner(() => { }, () => { }, () => { }));
        Assert.True(registration.ReportProgress(new ScanProgress
        {
            ScanType = ScanType.Quick, TotalFiles = 12, ScannedFiles = 3,
            ProgressPercent = 25, CurrentFile = "Initial observation", ElapsedTime = TimeSpan.FromMilliseconds(200)
        }));
        var reportAtOwnerBoundary = typeof(ScanCoordinatorService).GetMethod("TryReportExternalProgress",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("External progress owner boundary was not found.");
        bool observerRetainedOwnership = false;
        object? acceptedAtBoundary = null;
        Display? beforePendingProgress = null;
        Display? afterPendingProgress = null;
        int progressAfterInitial = 0;
        int terminalNotifications = 0;
        coordinator.ProgressChanged += _ => progressAfterInitial++;
        coordinator.ScanCompleted += _ =>
        {
            terminalNotifications++;
            observerRetainedOwnership = coordinator.IsExternalScanRunning;
            beforePendingProgress = Capture(coordinator);
            // The public ended check happened before completion. Invoking only the owner boundary
            // reproduces the preempted caller deterministically without scheduling live threads.
            acceptedAtBoundary = reportAtOwnerBoundary.Invoke(coordinator,
            [registration, new ScanProgress { ScanType = ScanType.Full, TotalFiles = 999, ScannedFiles = 998,
                ProgressPercent = 1, CurrentFile = "Late observation", ElapsedTime = TimeSpan.FromDays(2) }]);
            afterPendingProgress = Capture(coordinator);
        };

        Assert.True(registration.Complete(new ScanResult
        { ScanType = ScanType.Quick, Status = status, TotalFiles = 12, ScannedFiles = 8, ElapsedMs = 450 }));

        Assert.True(observerRetainedOwnership);
        Assert.False(Assert.IsType<bool>(acceptedAtBoundary));
        Assert.NotNull(beforePendingProgress);
        Assert.Equal(beforePendingProgress, afterPendingProgress);
        Assert.Equal(beforePendingProgress, Capture(coordinator));
        Assert.Equal(expectedState, coordinator.State);
        Assert.Equal(ScanType.Quick, coordinator.CurrentScanType);
        Assert.Equal(12, coordinator.TotalFiles);
        Assert.Equal(8, coordinator.ScannedFiles);
        Assert.Equal(TimeSpan.FromMilliseconds(450), coordinator.ElapsedTime);
        Assert.Equal(0, progressAfterInitial);
        Assert.Equal(1, terminalNotifications);
        Assert.False(coordinator.IsExternalScanRunning);
        Assert.Null(coordinator.CurrentSession);
    }

    private static Display Capture(ScanCoordinatorService coordinator) => new(coordinator.State, coordinator.StopReason,
        coordinator.CurrentScanType, coordinator.ProgressPercent, coordinator.CurrentFile, coordinator.ScannedFiles,
        coordinator.TotalFiles, coordinator.ElapsedTime, coordinator.StatusText);

    private sealed record Display(ScanState State, ScanStopReason StopReason, ScanType ScanType, double Progress,
        string CurrentFile, int ScannedFiles, int TotalFiles, TimeSpan Elapsed, string StatusText);

    private sealed class NoScan : IFileScanner
    {
        /// <inheritdoc />
        public bool IsPaused => false;
        /// <inheritdoc />
        public void PauseScan() => throw new InvalidOperationException("The external fixture owns its own scanner.");
        /// <inheritdoc />
        public void ResumeScan() => throw new InvalidOperationException("The external fixture owns its own scanner.");
        /// <inheritdoc />
        public Task<SecurityFinding?> ScanFileAsync(string path, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("No file inspection belongs to this fixture.");
        /// <inheritdoc />
        public Task<FileScanDetailedResult> ScanFileDetailedAsync(string path, TimeSpan perFileTimeout,
            CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("No file inspection belongs to this fixture.");
        /// <inheritdoc />
        public Task<ScanResult> ScanDirectoryAsync(string path, ScanType scanType, IProgress<ScanProgress>? progress = null,
            CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("No directory inspection belongs to this fixture.");
    }
}
