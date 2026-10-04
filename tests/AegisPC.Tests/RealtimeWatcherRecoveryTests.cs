using System.IO;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Contracts.Services;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests;

/// <summary>
/// Exercises user-mode watcher lifecycle and coverage reporting using harmless temporary files.
/// These checks do not establish pre-access blocking or malware detection effectiveness.
/// </summary>
public sealed class RealtimeWatcherRecoveryTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisWatcherReview_" + Guid.NewGuid().ToString("N"));

    /// <summary>Creates an isolated watcher root without changing installed protection settings.</summary>
    public RealtimeWatcherRecoveryTests() => Directory.CreateDirectory(_root);

    /// <summary>Verifies that adding and removing the only active root updates the reported coverage state.</summary>
    [Fact]
    public void AddingAndRemovingLastRootUpdatesCoverageHealth()
    {
        using var engine = CreateEngine();
        var health = new List<bool>();
        engine.OnProtectionHealthChanged += (covered, _) => health.Add(covered);

        engine.Start(watchDefaultLocations: false);
        Assert.False(health[^1]);

        engine.AddWatchDirectory(_root);
        Assert.True(health[^1]);
        Assert.Single(engine.WatchedLocations);

        engine.RemoveWatchDirectory(_root);
        Assert.False(health[^1]);
        Assert.Empty(engine.WatchedLocations);
    }

    /// <summary>Confirms an attached OS watcher forwards a harmless file arrival into the real event pipeline.</summary>
    [Fact]
    public async Task NewlyAttachedWatcherObservesBenignArrival()
    {
        using var engine = CreateEngine();
        var seen = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        engine.OnActivityLogged += activity =>
        {
            if (activity.Stage == "FILE_DETECTED") seen.TrySetResult(activity.FilePath);
        };

        engine.Start(watchDefaultLocations: false);
        engine.AddWatchDirectory(_root);
        string arrival = Path.Combine(_root, "arrival.bin");
        await File.WriteAllTextAsync(arrival, "Harmless watcher fixture.");

        Assert.Equal(arrival, await seen.Task.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    /// <summary>Checks that recovery cannot cross into a sibling directory sharing the root name prefix.</summary>
    [Fact]
    public void RecoveryRootMatchingHonorsExactRootAndDirectoryBoundary()
    {
        string watched = Path.Combine(_root, "watched");
        Directory.CreateDirectory(watched);
        using var engine = CreateEngine();
        engine.Start(watchDefaultLocations: false);
        engine.AddWatchDirectory(watched);

        var matcher = typeof(RealTimeProtectionEngine).GetMethod("FindWatchedRoot",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Watcher root matching method was not found.");
        string? Match(string path) => matcher.Invoke(engine, new object[] { path }) as string;

        string registeredRoot = Assert.Single(engine.WatchedLocations);
        Assert.Equal(registeredRoot, Match(watched));
        Assert.Equal(registeredRoot, Match(Path.Combine(watched, "sub", "nested.bin")));
        Assert.Null(Match(Path.Combine(_root, "watched-extra", "unrelated.bin")));
    }

    /// <summary>A fatal shared-resource error leaves a persistent gap even after the sole recovery root left the queue.</summary>
    [Fact]
    public async Task FatalRecoverySlotFailure_WithEmptyRemainingQueue_RetainsCoverageGap()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "existing.bin"), "Harmless recovery fixture.");
        using var engine = CreateEngine();
        var resources = new FailingResources();
        typeof(RealTimeProtectionEngine).GetField("_backgroundResources",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.SetValue(engine, resources);
        engine.Start(watchDefaultLocations: false);
        engine.AddWatchDirectory(_root);
        typeof(RealTimeProtectionEngine).GetMethod("RequestDirectoryInspection",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.Invoke(engine, new object[] { _root });

        await resources.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (engine.CaptureCoverage().RecoveryPending) await Task.Delay(10, deadline.Token);

        Assert.True(engine.CaptureCoverage().HasPersistentGap);
        Assert.Equal(1, engine.CaptureCoverage().WatcherCount);
    }

    /// <summary>A deferred fatal error from a stopped recovery generation cannot poison replacement engine coverage.</summary>
    [Fact]
    public async Task FatalOldRecoveryGeneration_DoesNotMarkNewGenerationDegraded()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "existing.bin"), "Harmless generation recovery fixture.");
        using var engine = CreateEngine();
        const System.Reflection.BindingFlags flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        var resources = new FailingResources { DeferFailure = true };
        typeof(RealTimeProtectionEngine).GetField("_backgroundResources", flags)!.SetValue(engine, resources);
        engine.Start(watchDefaultLocations: false);
        engine.AddWatchDirectory(_root);
        long generation = (long)typeof(RealTimeProtectionEngine).GetField("_engineGeneration", flags)!.GetValue(engine)!;
        var engineCancellation = (CancellationTokenSource)typeof(RealTimeProtectionEngine).GetField("_engineCts", flags)!.GetValue(engine)!;
        var roots = (HashSet<string>)typeof(RealTimeProtectionEngine).GetField("_reconciliationRoots", flags)!.GetValue(engine)!;
        roots.Add(_root);
        typeof(RealTimeProtectionEngine).GetField("_reconciliationRunning", flags)!.SetValue(engine, true);
        var recovery = (Task)typeof(RealTimeProtectionEngine).GetMethod("ReconcileArrivalsAsync", flags)!
            .Invoke(engine, new object[] { generation, engineCancellation.Token })!;
        await resources.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        engine.Stop();
        engine.Start(watchDefaultLocations: false);
        engine.AddWatchDirectory(_root);
        resources.Release.TrySetResult(true);
        await recovery.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(engine.CaptureCoverage().HasPersistentGap);
        Assert.False(engine.CaptureCoverage().RecoveryPending);
        Assert.Equal(1, engine.CaptureCoverage().WatcherCount);
    }

    private static RealTimeProtectionEngine CreateEngine() => new(
        new RealTimeEventIngestor(32), new Stable(), new IncompleteVerdict(), new NoAction());

    /// <summary>Removes the isolated temporary root after each test.</summary>
    public void Dispose() => Directory.Delete(_root, recursive: true);

    private sealed class Stable : IRealTimeStabilityChecker
    {
        public Task<bool> WaitForFileStabilityAsync(string filePath, CancellationToken ct) => Task.FromResult(true);
    }

    private sealed class IncompleteVerdict : IRealTimeVerdictProcessor
    {
        public Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default) =>
            Task.FromResult(new RealTimeVerdictResult { Verdict = RealTimeVerdict.Unknown, RecommendedPolicy = RealTimePolicyAction.Observe });

        public void CleanupCache() { }
    }

    private sealed class NoAction : IRealTimePolicyEnforcer
    {
        public event Action<SecurityFinding>? OnThreatDetected { add { } remove { } }
        public event Action<SecurityIncident>? OnIncidentCreated { add { } remove { } }
        public event Action<string, string, string>? OnNotificationRaised { add { } remove { } }
        public Task EnforceWarningAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct) => Task.CompletedTask;
        public Task EnforceQuarantineAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class FailingResources : IScanResourceManager
    {
        internal TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool DeferFailure { get; init; }
        /// <inheritdoc />
        public ScanResourceMode CurrentMode => ScanResourceMode.Balanced;
        /// <inheritdoc />
        public ScanResourceProfile ActiveProfile { get; } = new() { Concurrency = 1 };
        /// <inheritdoc />
        public event Action<ScanResourceProfile>? ProfileChanged { add { } remove { } }
        /// <inheritdoc />
        public void SetMode(ScanResourceMode mode) { }
        /// <inheritdoc />
        public async Task EnterWorkerSlotAsync(CancellationToken cancellationToken)
        {
            Entered.TrySetResult(true);
            if (DeferFailure) await Release.Task.ConfigureAwait(false);
            throw new IOException("Inert recovery slot failure.");
        }
        /// <inheritdoc />
        public void ExitWorkerSlot() => throw new InvalidOperationException("An unacquired slot cannot be released.");
        /// <inheritdoc />
        public Task ApplyPacingAsync(int processedFileCounter, CancellationToken cancellationToken) => Task.CompletedTask;
        /// <inheritdoc />
        public void RefreshProfile() { }
    }
}
