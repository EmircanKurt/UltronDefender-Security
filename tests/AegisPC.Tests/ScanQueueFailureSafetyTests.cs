using System.Collections.Concurrent;
using System.IO;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Benign queue infrastructure tests; no malware, process intervention or live service is used.</summary>
public sealed class ScanQueueFailureSafetyTests
{
    /// <summary>Opaque bytes with a media extension still reach the common scanner rather than a producer-side clean shortcut.</summary>
    [Fact]
    public async Task OpaqueJpg_ReachesCommonScanCallback()
    {
        string folder = Path.Combine(Path.GetTempPath(), "UltronQueueFixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string path = Path.Combine(folder, "opaque.jpg");
        byte[] opaque = [0x19, 0x23, 0x72, 0x04, 0x55, 0x61];
        try
        {
            await File.WriteAllBytesAsync(path, opaque);
            using var resources = new FixtureResources();
            using var queue = new ScanQueueCoordinator(resources);
            int calls = 0;
            var result = await queue.ExecuteScanQueueDetailedAsync(folder, ScanType.Custom,
                enqueue => enqueue(path), async (file, token) =>
                {
                    Assert.Equal(path, file);
                    Assert.Equal(opaque, await File.ReadAllBytesAsync(file, token));
                    Interlocked.Increment(ref calls);
                    return FileScanDetailedResult.CreateSuccess(file, null, TimeSpan.Zero);
                }, [], (_, _, _, _, _, _) => { }, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1, calls);
            Assert.Equal(1, result.ScannedFiles);
            Assert.Equal(0, result.SkippedFiles);
            Assert.Equal(0, queue.SkippedSignedClean);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
            Directory.Delete(folder);
        }
    }

    /// <summary>A fatal scanner exception aborts a producer that would otherwise block forever on the bounded writer.</summary>
    [Fact]
    public async Task FatalWorker_AbortsBlockedProducerAndSurfacesOriginalFailure()
    {
        using var resources = new FixtureResources();
        using var queue = new ScanQueueCoordinator(resources);
        var expected = new InvalidOperationException("fixture fatal scanner");
        var scan = queue.ExecuteScanQueueDetailedAsync("", ScanType.Full, ProduceMany,
            (_, _) => Task.FromException<FileScanDetailedResult>(expected), [], (_, _, _, _, _, _) => { }, CancellationToken.None);
        var observed = await Assert.ThrowsAsync<InvalidOperationException>(() => scan.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Same(expected, observed);
        Assert.Equal(0, queue.PendingFiles);
        Assert.Equal(0, queue.ActiveWorkers);
        Assert.Equal(0, queue.EffectiveWorkerLimit);
        Assert.Equal(0, resources.ActiveSlots);
        Assert.Equal(resources.EnterCount, resources.ExitCount);
    }

    /// <summary>Directory/source failure is not converted into a successful zero-threat scan result.</summary>
    [Fact]
    public async Task FatalProducer_IsRethrownAfterCleanup()
    {
        using var resources = new FixtureResources();
        using var queue = new ScanQueueCoordinator(resources);
        var expected = new IOException("fixture source failure");
        var scan = queue.ExecuteScanQueueDetailedAsync("", ScanType.Quick,
            _ => Task.FromException(expected), Success, [], (_, _, _, _, _, _) => { }, CancellationToken.None);
        var observed = await Assert.ThrowsAsync<IOException>(() => scan.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Same(expected, observed);
        Assert.Equal(0, queue.PendingFiles);
        Assert.Equal(0, queue.ActiveWorkers);
    }

    /// <summary>UI/progress errors are isolated so they cannot silently kill every worker or leave the writer blocked.</summary>
    [Fact]
    public async Task ThrowingProgressObserver_DoesNotStopAnalysisOrHangProducer()
    {
        using var resources = new FixtureResources();
        using var queue = new ScanQueueCoordinator(resources);
        int progress = 0;
        var result = await queue.ExecuteScanQueueDetailedAsync("", ScanType.Full,
            async enqueue => { for (int index = 0; index < 200; index++) await enqueue(@"C:\fixture\" + index + ".bin"); },
            Success, [], (_, _, _, _, _, _) => { Interlocked.Increment(ref progress); throw new InvalidOperationException("fixture UI callback"); },
            CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(200, result.TotalFiles);
        Assert.Equal(200, result.ScannedFiles);
        Assert.Equal(200, progress);
        Assert.Equal(0, resources.ActiveSlots);
        Assert.Equal(resources.EnterCount, resources.ExitCount);
        Assert.Equal(0, queue.PendingFiles);
    }

    /// <summary>Resource-slot failure is fatal and also cancels a bounded producer instead of starving its writer.</summary>
    [Fact]
    public async Task FatalSlotAcquisition_AbortsProducerWithoutLeakingPendingCount()
    {
        using var resources = new FixtureResources { ThrowOnEnter = true };
        using var queue = new ScanQueueCoordinator(resources);
        var scan = queue.ExecuteScanQueueDetailedAsync("", ScanType.Full, ProduceMany, Success,
            [], (_, _, _, _, _, _) => { }, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(() => scan.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(0, queue.PendingFiles);
        Assert.Equal(0, queue.ActiveWorkers);
        Assert.Equal(0, resources.ActiveSlots);
    }

    /// <summary>Pacing failure remains a failed scan while already-acquired slots are released.</summary>
    [Fact]
    public async Task FatalPacing_AbortsSiblingsAndReleasesSlots()
    {
        using var resources = new FixtureResources { ThrowOnPacing = true };
        using var queue = new ScanQueueCoordinator(resources);
        var scan = queue.ExecuteScanQueueDetailedAsync("", ScanType.Full, ProduceMany, Success,
            [], (_, _, _, _, _, _) => { }, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(() => scan.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(0, resources.ActiveSlots);
        Assert.Equal(resources.EnterCount, resources.ExitCount);
        Assert.Equal(0, queue.PendingFiles);
    }

    /// <summary>Failure before worker startup still clears the active resource profile shown by telemetry.</summary>
    [Fact]
    public async Task FatalResourceConfiguration_ClearsActiveProfile()
    {
        using var resources = new FixtureResources { ThrowOnConfigure = true };
        using var queue = new ScanQueueCoordinator(resources);
        await Assert.ThrowsAsync<InvalidOperationException>(() => queue.ExecuteScanQueueDetailedAsync("", ScanType.Quick,
            ProduceMany, Success, [], (_, _, _, _, _, _) => { }, CancellationToken.None));
        Assert.Equal(0, queue.EffectiveWorkerLimit);
        Assert.Equal(0, queue.PendingFiles);
        Assert.Equal(0, queue.ActiveWorkers);
    }

    /// <summary>Unrequested source cancellation is a pipeline failure, not an ordinary user-cancelled scan.</summary>
    [Fact]
    public async Task ForeignSourceCancellation_IsNotReportedAsUserCancellation()
    {
        using var resources = new FixtureResources();
        using var queue = new ScanQueueCoordinator(resources);
        var scan = queue.ExecuteScanQueueDetailedAsync("", ScanType.Quick,
            _ => Task.FromException(new OperationCanceledException("fixture unrelated token")), Success,
            [], (_, _, _, _, _, _) => { }, CancellationToken.None);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => scan.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.IsType<OperationCanceledException>(error.InnerException);
    }

    /// <summary>Requested cancellation cooperatively ends scan work and releases all queue/resource accounting.</summary>
    [Fact]
    public async Task RequestedCancellation_ExitsCleanlyAndClearsCounters()
    {
        using var resources = new FixtureResources();
        using var queue = new ScanQueueCoordinator(resources);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var scan = queue.ExecuteScanQueueDetailedAsync("", ScanType.Full, ProduceMany, async (file, token) =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return FileScanDetailedResult.CreateSuccess(file, null, TimeSpan.Zero);
        }, [], (_, _, _, _, _, _) => { }, cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await scan.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, resources.ActiveSlots);
        Assert.Equal(resources.EnterCount, resources.ExitCount);
        Assert.Equal(0, queue.ActiveWorkers);
        Assert.Equal(0, queue.PendingFiles);
    }

    private static async Task ProduceMany(Func<string, Task> enqueue)
    {
        for (int index = 0; index < 2000; index++) await enqueue(@"C:\fixture\" + index + ".bin");
    }

    private static Task<FileScanDetailedResult> Success(string path, CancellationToken _) =>
        Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero));

    private sealed class FixtureResources : IScanResourceManager, IDisposable
    {
        private readonly SemaphoreSlim _slots = new(1, 1);
        private int _active;
        private int _enters;
        private int _exits;
        internal bool ThrowOnEnter { get; init; }
        internal bool ThrowOnPacing { get; init; }
        internal bool ThrowOnConfigure { get; init; }
        internal int ActiveSlots => Volatile.Read(ref _active);
        internal int EnterCount => Volatile.Read(ref _enters);
        internal int ExitCount => Volatile.Read(ref _exits);
        public ScanResourceMode CurrentMode => ScanResourceMode.Balanced;
        public ScanResourceProfile ActiveProfile { get; } = new() { Concurrency = 1, ChannelCapacity = 1, YieldFrequency = 1, SummaryText = "inert fixture" };
        public event Action<ScanResourceProfile>? ProfileChanged { add { } remove { } }
        public void SetMode(ScanResourceMode mode) { }
        public void ConfigureTarget(string targetPath) { if (ThrowOnConfigure) throw new InvalidOperationException("fixture configure failure"); }
        public void RefreshProfile() { }
        public async Task EnterWorkerSlotAsync(CancellationToken token)
        {
            if (ThrowOnEnter) throw new InvalidOperationException("fixture slot failure");
            await _slots.WaitAsync(token);
            Interlocked.Increment(ref _active);
            Interlocked.Increment(ref _enters);
        }
        public void ExitWorkerSlot()
        {
            Interlocked.Decrement(ref _active);
            Interlocked.Increment(ref _exits);
            _slots.Release();
        }
        public Task ApplyPacingAsync(int processedFileCounter, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (ThrowOnPacing) throw new InvalidOperationException("fixture pacing failure");
            return Task.CompletedTask;
        }
        public void Dispose() => _slots.Dispose();
    }
}
