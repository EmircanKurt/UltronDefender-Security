using System.Collections.Concurrent;
using System.IO;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Temporary-file user-mode media orchestration fixtures, not physical USB or malware effectiveness tests.</summary>
public sealed class RealtimeMediaInspectionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisMediaFixture_" + Guid.NewGuid().ToString("N"));

    /// <summary>Creates only this test's harmless isolated directory.</summary>
    public RealtimeMediaInspectionTests() => Directory.CreateDirectory(_root);

    /// <summary>Existing opaque files and nested content reach the common file path after the watcher is attached.</summary>
    [Fact]
    public async Task InitialInspection_AttachesWatcherBeforeInspectingExistingFiles()
    {
        string first = Path.Combine(_root, "opaque.jpg");
        string nested = Path.Combine(_root, "nested");
        Directory.CreateDirectory(nested);
        string second = Path.Combine(nested, "existing.bin");
        await File.WriteAllTextAsync(first, "Harmless opaque payload, not a JPEG.");
        await File.WriteAllTextAsync(second, "Harmless existing nested fixture.");
        var observed = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        RealTimeProtectionEngine? activeEngine = null;
        using var engine = CreateEngine(new FixtureVerdict(async (path, ct) =>
        {
            Assert.Contains(NormalizedRoot(), activeEngine!.WatchedLocations);
            Assert.NotEmpty(await File.ReadAllTextAsync(path, ct));
            observed[path] = true;
            return Clean();
        }));
        activeEngine = engine;
        engine.Start(watchDefaultLocations: false);
        Guid generation = Guid.NewGuid();

        await engine.InspectMediaAsync(_root, generation, CancellationToken.None);

        Assert.Equal(2, observed.Count);
        Assert.Contains(first, observed.Keys);
        Assert.Contains(second, observed.Keys);
        var snapshot = Assert.Single(engine.GetMediaInspections());
        Assert.Equal(generation, snapshot.Generation);
        Assert.Equal("Completed", snapshot.State);
        Assert.Equal(2, snapshot.AttemptedFiles);
        Assert.Equal(0, snapshot.IncompleteFiles);
        Assert.Single(engine.WatchedLocations);
    }

    /// <summary>A synthetic Unknown verdict produces partial inspection and a persistent coverage gap, never a clean claim.</summary>
    [Fact]
    public async Task UnknownExistingFile_RemainsPartialCoverage()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "opaque.bin"), "Harmless unknown fixture.");
        var policy = new NoAction();
        using var engine = CreateEngine(new FixtureVerdict((_, _) => Task.FromResult(new RealTimeVerdictResult
            { Verdict = RealTimeVerdict.Unknown, RecommendedPolicy = RealTimePolicyAction.Observe })), policy);
        engine.Start(watchDefaultLocations: false);

        await engine.InspectMediaAsync(_root, Guid.NewGuid(), CancellationToken.None);

        var snapshot = Assert.Single(engine.GetMediaInspections());
        Assert.Equal("Partial", snapshot.State);
        Assert.Equal(1, snapshot.IncompleteFiles);
        Assert.True(engine.CaptureCoverage().HasPersistentGap);
        Assert.False(engine.CaptureCoverage().RecoveryPending);
        Assert.Equal(0, policy.QuarantineCalls);
    }

    /// <summary>Insertion cancellation aborts a blocked inspection and never marks that insertion Completed.</summary>
    [Fact]
    public async Task InsertionCancellation_CancelsInitialInspection()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "existing.bin"), "Harmless cancellation fixture.");
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var engine = CreateEngine(new FixtureVerdict(async (_, ct) =>
        { entered.TrySetResult(true); await Task.Delay(Timeout.Infinite, ct); return Clean(); }));
        engine.Start(watchDefaultLocations: false);
        using var insertion = new CancellationTokenSource();
        Guid generation = Guid.NewGuid();

        var scan = engine.InspectMediaAsync(_root, generation, insertion.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        insertion.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scan.WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal("Cancelled", Assert.Single(engine.GetMediaInspections()).State);
        engine.RemoveMedia(generation);
        Assert.Empty(engine.GetMediaInspections());
        Assert.Empty(engine.WatchedLocations);
    }

    /// <summary>A cancelled insertion cannot attach a watcher or create an inspection record before starting.</summary>
    [Fact]
    public async Task PreCancelledInsertion_DoesNotAttachWatcher()
    {
        using var engine = CreateEngine(new FixtureVerdict((_, _) => Task.FromResult(Clean())));
        engine.Start(watchDefaultLocations: false);
        using var insertion = new CancellationTokenSource();
        insertion.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.InspectMediaAsync(_root, Guid.NewGuid(), insertion.Token));

        Assert.Empty(engine.WatchedLocations);
        Assert.Empty(engine.GetMediaInspections());
    }

    /// <summary>Removing an older completed insertion does not detach the same root now owned by a newer insertion.</summary>
    [Fact]
    public async Task OldGenerationRemoval_PreservesNewGenerationWatcher()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "existing.bin"), "Harmless generation fixture.");
        using var engine = CreateEngine(new FixtureVerdict((_, _) => Task.FromResult(Clean())));
        engine.Start(watchDefaultLocations: false);
        Guid oldGeneration = Guid.NewGuid();
        Guid newGeneration = Guid.NewGuid();
        await engine.InspectMediaAsync(_root, oldGeneration, CancellationToken.None);
        await engine.InspectMediaAsync(_root, newGeneration, CancellationToken.None);

        engine.RemoveMedia(oldGeneration);

        Assert.Equal(newGeneration, Assert.Single(engine.GetMediaInspections()).Generation);
        Assert.Single(engine.WatchedLocations);
        engine.RemoveMedia(newGeneration);
        Assert.Empty(engine.WatchedLocations);
    }

    /// <summary>Direct removal cancels its own running inspection without cancelling a newer insertion sharing the root.</summary>
    [Fact]
    public async Task Removal_CancelsOnlyItsRunningGeneration()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "existing.bin"), "Harmless removal fixture.");
        int calls = 0;
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var engine = CreateEngine(new FixtureVerdict(async (_, ct) =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            { entered.TrySetResult(true); await Task.Delay(Timeout.Infinite, ct); }
            return Clean();
        }));
        engine.Start(watchDefaultLocations: false);
        Guid oldGeneration = Guid.NewGuid();
        Guid newGeneration = Guid.NewGuid();
        var oldScan = engine.InspectMediaAsync(_root, oldGeneration, CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var newScan = engine.InspectMediaAsync(_root, newGeneration, CancellationToken.None);

        engine.RemoveMedia(oldGeneration);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => oldScan.WaitAsync(TimeSpan.FromSeconds(5)));
        await newScan.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Single(engine.WatchedLocations);
        var snapshot = Assert.Single(engine.GetMediaInspections());
        Assert.Equal(newGeneration, snapshot.Generation);
        Assert.Equal("Completed", snapshot.State);
    }

    private string NormalizedRoot() => Path.GetFullPath(_root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

    /// <summary>Implicit network events never reach stability/content analysis and remain an explicit coverage gap.</summary>
    [Fact]
    public async Task ImplicitNetworkEvent_DoesNotReachContentProcessor()
    {
        int inspections = 0;
        using var engine = CreateEngine(new FixtureVerdict((_, _) =>
        { Interlocked.Increment(ref inspections); return Task.FromResult(Clean()); }));
        engine.Start(watchDefaultLocations: false);
        var evt = new NormalizedFileEvent { FilePath = @"\\server.invalid\share\file", NormalizedPath = @"\\server.invalid\share\file",
            EventType = RealTimeEventType.Created };
        var method = typeof(RealTimeProtectionEngine).GetMethod("HandleNormalizedEventAsync",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        bool inspected = await (Task<bool>)method.Invoke(engine, [evt, CancellationToken.None])!;
        Assert.False(inspected);
        Assert.Equal(0, inspections);
        Assert.True(engine.CaptureCoverage().HasPersistentGap);
    }
    private static RealTimeVerdictResult Clean() => new() { Verdict = RealTimeVerdict.Clean, RecommendedPolicy = RealTimePolicyAction.Allow };
    private static RealTimeProtectionEngine CreateEngine(FixtureVerdict verdict, NoAction? policy = null) =>
        new(new RealTimeEventIngestor(32), new Stable(), verdict, policy ?? new NoAction());

    /// <summary>Removes only this instance's isolated fixture after its engine/watchers have been disposed.</summary>
    public void Dispose() => Directory.Delete(_root, recursive: true);

    private sealed class Stable : IRealTimeStabilityChecker
    {
        /// <inheritdoc />
        public Task<bool> WaitForFileStabilityAsync(string filePath, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return Task.FromResult(true); }
    }

    private sealed class FixtureVerdict(Func<string, CancellationToken, Task<RealTimeVerdictResult>> inspect) : IRealTimeVerdictProcessor
    {
        /// <inheritdoc />
        public Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default) => inspect(filePath, ct);
        /// <inheritdoc />
        public void CleanupCache() { }
    }

    private sealed class NoAction : IRealTimePolicyEnforcer
    {
        internal int QuarantineCalls;
        /// <inheritdoc />
        public event Action<SecurityFinding>? OnThreatDetected { add { } remove { } }
        /// <inheritdoc />
        public event Action<SecurityIncident>? OnIncidentCreated { add { } remove { } }
        /// <inheritdoc />
        public event Action<string, string, string>? OnNotificationRaised { add { } remove { } }
        /// <inheritdoc />
        public Task EnforceWarningAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct) => Task.CompletedTask;
        /// <inheritdoc />
        public Task EnforceQuarantineAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct)
        { Interlocked.Increment(ref QuarantineCalls); return Task.CompletedTask; }
    }
}
