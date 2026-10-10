using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks truthful queue and worker telemetry without creating malware or touching the installed scanner.</summary>
public sealed class ManualScanResourceTelemetryTests
{
    /// <summary>Waiting files stay pending until they obtain an actual analysis slot, then all counters return to zero.</summary>
    [Fact]
    public async Task QueueTelemetry_ReportsWaitingFilesAndActualWorkers()
    {
        using var manager = new AdaptiveScanResourceManager(
            pressureSampler: () => (0, 0, false),
            enableTelemetryTimer: false,
            storageClassifier: _ => true);
        manager.SetMode(ScanResourceMode.VeryLow);
        using var coordinator = new ScanQueueCoordinator(manager);
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var produced = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var scan = coordinator.ExecuteScanQueueDetailedAsync(
            string.Empty,
            ScanType.Custom,
            async queue =>
            {
                for (int i = 0; i < 6; i++) await queue($"C:\\benign-{i}.dat");
                produced.TrySetResult(true);
            },
            async (path, token) =>
            {
                entered.TrySetResult(true);
                await release.Task.WaitAsync(token);
                return FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero);
            },
            new ConcurrentBag<SecurityFinding>(),
            (_, _, _, _, _, _) => { },
            cts.Token);

        try
        {
            await Task.WhenAll(entered.Task, produced.Task).WaitAsync(cts.Token);
            Assert.Equal(1, coordinator.EffectiveWorkerLimit);
            Assert.Equal(1, coordinator.ActiveWorkers);
            Assert.Equal(5, coordinator.PendingFiles);
        }
        finally
        {
            release.TrySetResult(true);
        }

        var result = await scan;
        Assert.Equal(6, result.TotalFiles);
        Assert.Equal(6, result.ScannedFiles);
        Assert.Equal(0, coordinator.ActiveWorkers);
        Assert.Equal(0, coordinator.PendingFiles);
    }

    /// <summary>Cancellation must not leave stale queue or active-worker figures in the UI.</summary>
    [Fact]
    public async Task QueueTelemetry_CancellationClearsCounters()
    {
        using var manager = new AdaptiveScanResourceManager(
            pressureSampler: () => (0, 0, false),
            enableTelemetryTimer: false,
            storageClassifier: _ => true);
        manager.SetMode(ScanResourceMode.VeryLow);
        using var coordinator = new ScanQueueCoordinator(manager);
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var produced = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var scan = coordinator.ExecuteScanQueueDetailedAsync(
            string.Empty,
            ScanType.Custom,
            async queue =>
            {
                for (int i = 0; i < 6; i++) await queue($"C:\\benign-{i}.dat");
                produced.TrySetResult(true);
            },
            async (path, token) =>
            {
                entered.TrySetResult(true);
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero);
            },
            new ConcurrentBag<SecurityFinding>(),
            (_, _, _, _, _, _) => { },
            cts.Token);

        await Task.WhenAll(entered.Task, produced.Task).WaitAsync(cts.Token);
        Assert.Equal(5, coordinator.PendingFiles);
        cts.Cancel();
        await scan.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, coordinator.ActiveWorkers);
        Assert.Equal(0, coordinator.PendingFiles);
        Assert.Equal(0, coordinator.EffectiveWorkerLimit);
    }
}
