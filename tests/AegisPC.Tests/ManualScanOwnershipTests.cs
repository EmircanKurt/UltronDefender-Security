using System;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks that resource-policy changes belong to a newly claimed manual scan only.</summary>
public sealed class ManualScanOwnershipTests
{
    /// <summary>A concurrent manual request cannot change the active scan's resource profile.</summary>
    [Fact]
    public async Task BusyManualScan_DoesNotApplySecondResourceProfile()
    {
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        int appliedProfiles = 0;

        var active = coordinator.TryStartManualScanAsync(ScanType.Quick, string.Empty,
            () => appliedProfiles++);
        await scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var competing = await coordinator.TryStartManualScanAsync(ScanType.Full, string.Empty,
            () => appliedProfiles += 100);

        Assert.Null(competing);
        Assert.Equal(1, appliedProfiles);
        Assert.Equal(ScanType.Quick, coordinator.CurrentScanType);
        scanner.Complete.TrySetResult(true);
        await active.WaitAsync(TimeSpan.FromSeconds(5));
    }

    /// <summary>A failed policy callback releases ownership before any scanner work starts.</summary>
    [Fact]
    public async Task ResourceProfileFailure_ReleasesManualOwnership()
    {
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            coordinator.TryStartManualScanAsync(ScanType.Quick, string.Empty,
                () => throw new InvalidOperationException("Synthetic profile failure")));

        Assert.Null(coordinator.CurrentSession);
        Assert.Equal(0, scanner.StartCount);
        var retry = coordinator.TryStartManualScanAsync(ScanType.Quick, string.Empty, () => { });
        await scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        scanner.Complete.TrySetResult(true);
        await retry.WaitAsync(TimeSpan.FromSeconds(5));
    }
}
