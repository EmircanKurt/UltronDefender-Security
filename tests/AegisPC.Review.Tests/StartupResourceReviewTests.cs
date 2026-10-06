using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Tests startup ownership and scope using benign temporary files and recording collaborators only.</summary>
public sealed partial class StartupSweepSafetyTests
{
    [Theory]
    [InlineData(RealTimeVerdict.Unknown, 50)]
    [InlineData(RealTimeVerdict.Suspicious, 40)]
    public async Task IncompleteOrObservation_IsNotAThreatCount(RealTimeVerdict verdict, int score)
    {
        var file = CreateBenignFile();
        var coordinator = new RecordingCoordinator();
        var vault = new RecordingVault();
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult { Verdict = verdict, RiskScore = score });
        var result = await new StartupSecuritySweepService(engine, vault, scanCoordinator: coordinator).RunSweepAsync([file]);
        Assert.Equal(0, result.ThreatsCount);
        Assert.Equal(0, result.SuspiciousCount);
        Assert.Empty(coordinator.LastResult!.Findings);
        Assert.Equal(verdict == RealTimeVerdict.Unknown ? 1 : 0, result.IncompleteCount);
        Assert.Equal(0, vault.BoundCalls);
    }

    [Fact]
    public async Task StartupParallelism_IsBounded_AndEveryScopedExtensionIsInspectedOnce()
    {
        Directory.CreateDirectory(_dir);
        string[] paths = ["a.jpg", "b.jar", "c", "d.dll", "e.txt", "f.exe", "g.zip", "h.png"];
        foreach (var name in paths) File.WriteAllText(Path.Combine(_dir, name), "inert fixture");
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0, peak = 0;
        var seen = new ConcurrentDictionary<string, int>();
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult())
        {
            AsyncInspect = async (path, token) =>
            {
                seen.AddOrUpdate(path, 1, (_, n) => n + 1);
                int count = Interlocked.Increment(ref active);
                int observed;
                do { observed = Volatile.Read(ref peak); } while (count > observed && Interlocked.CompareExchange(ref peak, count, observed) != observed);
                if (count == 4) entered.TrySetResult();
                try { await release.Task.WaitAsync(token); return new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean, SHA256 = ValidHash(path) }; }
                finally { Interlocked.Decrement(ref active); }
            }
        };
        var sweep = new StartupSecuritySweepService(engine, new RecordingVault(),
            resourceManagerFactory: () => new FixedResources(4), storageClassifier: _ => true);
        int completions = 0;
        sweep.OnSweepCompleted += _ => completions++;
        var work = sweep.RunSweepAsync([_dir]);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(4, active);
            release.TrySetResult();
            var result = await work.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(8, result.TotalScanned);
            Assert.Equal(4, peak);
            Assert.Equal(8, seen.Count);
            Assert.All(seen.Values, value => Assert.Equal(1, value));
            Assert.Equal(1, completions);
            Assert.Equal(0, active);
        }
        finally { release.TrySetResult(); await work; }
    }

    private sealed class FixedResources(int workers) : IScanResourceManager, IDisposable
    {
        private readonly SemaphoreSlim _gate = new(workers, workers);
        public ScanResourceMode CurrentMode => ScanResourceMode.Auto;
        public ScanResourceProfile ActiveProfile => new() { Concurrency = workers, MaximumConcurrency = workers, MaxMemoryBudgetBytes = 2L << 30 };
        public event Action<ScanResourceProfile>? ProfileChanged { add { } remove { } }
        public void SetMode(ScanResourceMode mode) { }
        public Task EnterWorkerSlotAsync(CancellationToken token) => _gate.WaitAsync(token);
        public void ExitWorkerSlot() => _gate.Release();
        public Task ApplyPacingAsync(int count, CancellationToken token) => Task.CompletedTask;
        public void RefreshProfile() { }
        public void Dispose() => _gate.Dispose();
    }

    [Fact]
    public async Task StartupCleanCache_DoesNotOutliveDetectionPolicy_AndFailuresRetainSafeDetails()
    {
        string file = CreateBenignFile();
        var engine = new RecordingEngine(path => new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean, SHA256 = ValidHash(path) });
        var coordinator = new RecordingCoordinator();
        var sweep = new StartupSecuritySweepService(engine, new RecordingVault(), scanCoordinator: coordinator);
        await sweep.RunSweepAsync([file]);
        await sweep.RunSweepAsync([file]);
        Assert.Equal(1, engine.Inspections);
        AegisPC.Security.DetectionPolicyRevision.Invalidate();
        engine.AsyncInspect = (_, _) => throw new InvalidOperationException("private fixture path must not appear in public diagnostics");
        var failed = await sweep.RunSweepAsync([file]);
        Assert.Equal(2, engine.Inspections);
        Assert.Equal(StartupSweepStatus.Failed, failed.FinalStatus);
        Assert.NotNull(coordinator.LastResult!.FailureInfo);
        Assert.DoesNotContain("private fixture", coordinator.LastResult.FailureInfo.SafeMessage);
        Assert.NotEqual(default, coordinator.LastResult.StartedAt);
    }
}
