using System;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks that a startup scanner cannot take over a manual coordinator session.</summary>
public sealed class ExternalScanOwnershipTests
{
    /// <summary>An active manual scan rejects external registration without changing its owner.</summary>
    [Fact]
    public async Task ManualScan_BlocksExternalClaim()
    {
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        var manual = coordinator.TryStartManualScanAsync(ScanType.Full, string.Empty, () => { });
        await scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var session = coordinator.CurrentSession;

        var external = coordinator.TryRegisterExternalScanner(() => { }, () => { }, () => { });

        Assert.Null(external);
        Assert.Same(session, coordinator.CurrentSession);
        Assert.Equal(ScanType.Full, coordinator.CurrentScanType);
        scanner.Complete.TrySetResult(true);
        await manual.WaitAsync(TimeSpan.FromSeconds(5));
    }

    /// <summary>An active external scan rejects manual profile changes and stale events after release.</summary>
    [Fact]
    public async Task ExternalClaim_BlocksManualAndStaleEventsCannotOverwriteNewManual()
    {
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        using var external = Assert.IsAssignableFrom<AegisPC.Contracts.Services.IExternalScanRegistration>(
            coordinator.TryRegisterExternalScanner(() => { }, () => { }, () => { }));

        int profileChanges = 0;
        var busy = await coordinator.TryStartManualScanAsync(ScanType.Full, string.Empty, () => profileChanges++);
        Assert.Null(busy);
        Assert.Equal(0, profileChanges);
        Assert.Equal(0, scanner.StartCount);
        Assert.True(external.ReportProgress(new ScanProgress { ScanType = ScanType.Quick, ScannedFiles = 4 }));
        Assert.True(external.Complete(new ScanResult { ScanType = ScanType.Quick, Status = ScanStatus.Completed }));

        var manual = coordinator.TryStartManualScanAsync(ScanType.Full, string.Empty, () => profileChanges++);
        await scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var session = coordinator.CurrentSession;
        Assert.False(external.ReportProgress(new ScanProgress { ScanType = ScanType.Quick, ScannedFiles = 999 }));
        Assert.False(external.Complete(new ScanResult { ScanType = ScanType.Quick, Status = ScanStatus.Completed }));
        external.Dispose();
        Assert.Same(session, coordinator.CurrentSession);
        Assert.Equal(ScanType.Full, coordinator.CurrentScanType);
        Assert.Equal(0, coordinator.ScannedFiles);
        Assert.Equal(1, profileChanges);
        scanner.Complete.TrySetResult(true);
        await manual.WaitAsync(TimeSpan.FromSeconds(5));
    }

    /// <summary>A disposed registration cannot cancel or replace a later external registration.</summary>
    [Fact]
    public void DisposedExternalRegistration_CannotReleaseSuccessor()
    {
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        var oldRegistration = Assert.IsAssignableFrom<AegisPC.Contracts.Services.IExternalScanRegistration>(
            coordinator.TryRegisterExternalScanner(() => { }, () => { }, () => { }));
        oldRegistration.Dispose();

        using var successor = Assert.IsAssignableFrom<AegisPC.Contracts.Services.IExternalScanRegistration>(
            coordinator.TryRegisterExternalScanner(() => { }, () => { }, () => { }));
        oldRegistration.Dispose();
        Assert.False(oldRegistration.ReportProgress(new ScanProgress { ScannedFiles = 999 }));
        Assert.True(successor.ReportProgress(new ScanProgress { ScannedFiles = 2 }));
        Assert.Equal(2, coordinator.ScannedFiles);
        Assert.True(coordinator.IsExternalScanRunning);
    }
}
