using System.Diagnostics;
using System.IO;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Protection;
using AegisPC.Security.Behavior;
using AegisPC.Security.UltronAI;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests;

/// <summary>Pure inert events; no live processes, termination, startup changes or native ETW sessions.</summary>
public sealed class BehaviorCorrelationReviewTests(ITestOutputHelper output)
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private static BehaviorProcessIdentity Actor(int pid = 100) => new(pid, Now.AddMinutes(-1), "inert-boot-A");
    private static BehaviorObservation Event(string id, BehaviorObservationKind kind, BehaviorProcessIdentity? actor,
        BehaviorAttribution attribution = BehaviorAttribution.Unknown, DateTimeOffset? time = null) =>
        new(id, kind.ToString(), kind, actor, time ?? Now, "Inert observation; not confirmed malware", attribution, 10);

    [Fact]
    public void LineagePidReuseCannotAttachOldChildrenOrDelayedExits()
    {
        var tracker = new ProcessLineageTracker();
        tracker.RegisterProcess(new() { Pid = 10, StartTimeUtc = Now.AddMinutes(-2).UtcDateTime, BootId = "A" });
        tracker.RegisterProcess(new() { Pid = 11, ParentPid = 10, StartTimeUtc = Now.AddMinutes(-1).UtcDateTime, BootId = "A" });
        Assert.Single(tracker.GetAncestors(11));
        tracker.RegisterProcess(new() { Pid = 10, StartTimeUtc = Now.UtcDateTime, BootId = "A" });
        Assert.Empty(tracker.GetAncestors(11)); Assert.Empty(tracker.GetDescendants(10));
        tracker.MarkTerminatedAt(10, Now.AddSeconds(-1).UtcDateTime);
        Assert.False(tracker.GetProcess(10)!.IsTerminated);
        var detached = tracker.GetProcess(10)!; detached.StartTimeUtc = DateTime.MinValue;
        Assert.Equal(Now.UtcDateTime, tracker.GetProcess(10)!.StartTimeUtc);
    }

    [Fact]
    public void CyclicAndDeepLineageIsBoundedWithoutRecursion()
    {
        var tracker = new ProcessLineageTracker();
        for (int i = 1; i <= 1000; i++) tracker.RegisterProcess(new()
        { Pid = i, ParentPid = i - 1, StartTimeUtc = Now.AddSeconds(-1001 + i).UtcDateTime, BootId = "A" });
        Assert.Equal(256, tracker.GetAncestors(1000).Count);
        Assert.Equal(256, tracker.GetDescendants(1).Count);
        tracker.RegisterProcess(new() { Pid = 1, ParentPid = 1000, StartTimeUtc = Now.UtcDateTime, BootId = "A" });
        Assert.True(tracker.GetAncestors(1).Count <= 256);
    }

    [Fact]
    public void WriterRequiresLiveThreadGenerationNotPidOrWatcherGuess()
    {
        var table = new EtwActorCorrelationTable(); var first = Actor();
        table.ProcessStarted(first); Assert.Null(table.ResolveWriter(200, Now));
        table.ThreadStarted(200, first.Pid, Now.AddSeconds(-30)); Assert.Equal(first, table.ResolveWriter(200, Now));
        var reused = first with { StartedAtUtc = Now.AddSeconds(-1) };
        table.ProcessStarted(reused); Assert.Null(table.ResolveWriter(200, Now));
        table.ThreadStarted(200, reused.Pid, Now);
        table.ThreadStopped(200, Now.AddSeconds(-2)); Assert.Equal(reused, table.ResolveWriter(200, Now));
        table.InvalidateContinuity(); Assert.Null(table.ResolveWriter(200, Now));
    }

    [Fact]
    public void RepeatedBackupBuildAndPowerShellWritesNeverAccumulateIntoNativeAction()
    {
        var correlator = new BehaviorWindowCorrelator(new UltronDecisionEngine());
        BehaviorWindowReview? review = null;
        for (int i = 0; i < 1000; i++) review = correlator.Observe(Event("benign-" + i,
            BehaviorObservationKind.FileWritten, Actor(), BehaviorAttribution.EtwThreadGeneration), Now);
        Assert.Equal(10, review!.LongWindow.ReviewPriority);
        Assert.Equal(ProtectionActionKind.Observe, review.LongWindow.Recommendation);
        Assert.True(review.Evictions > 0); Assert.False(review.AttributionComplete);
        Assert.NotNull(correlator.Statistics.Ewma);
    }

    [Fact]
    public void UnknownActorAndFileWatcherCannotEnterCorrelatedChain()
    {
        var correlator = new BehaviorWindowCorrelator(new UltronDecisionEngine());
        var review = correlator.Observe(Event("watcher", BehaviorObservationKind.FileWritten, Actor()), Now);
        Assert.Null(review.Actor); Assert.False(review.AttributionComplete); Assert.Equal(0, review.RetainedActors);
        review = correlator.Observe(Event("missing", BehaviorObservationKind.ProcessStarted, Actor() with { BootId = "" }), Now);
        Assert.False(review.AttributionComplete);
    }

    [Fact]
    public void SeparateWindowsAndBootsNeverMergeEvidence()
    {
        var correlator = new BehaviorWindowCorrelator(new UltronDecisionEngine()); var actor = Actor();
        correlator.Observe(Event("old", BehaviorObservationKind.ProcessStarted, actor, time: Now.AddSeconds(-40)), Now);
        var review = correlator.Observe(Event("new", BehaviorObservationKind.FileWritten, actor, BehaviorAttribution.EtwThreadGeneration), Now);
        Assert.Equal(10, review.ShortWindow.ReviewPriority); Assert.Equal(20, review.LongWindow.ReviewPriority);
        review = correlator.Observe(Event("other-boot", BehaviorObservationKind.StartupChanged, actor with { BootId = "B" }), Now);
        Assert.Equal(10, review.LongWindow.ReviewPriority); Assert.Equal(2, review.RetainedActors);
        Assert.DoesNotContain(review.LongWindow.Recommendation, new[] { ProtectionActionKind.TerminateVerifiedActor, ProtectionActionKind.Quarantine });
    }

    [Fact]
    public async Task BoundedQueueReportsLossAndCancellation()
    {
        var source = new BoundedBehaviorObservationSource(1);
        Assert.True(source.TryPublish(Event("1", BehaviorObservationKind.ProcessStarted, Actor())));
        Assert.False(source.TryPublish(Event("2", BehaviorObservationKind.ProcessStarted, Actor())));
        Assert.Equal(1, source.CaptureHealth().Dropped);
        using var cts = new CancellationTokenSource();
        await using var consumer = source.ReadAllAsync(cts.Token).GetAsyncEnumerator();
        Assert.True(await consumer.MoveNextAsync()); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => consumer.MoveNextAsync().AsTask());
    }

    [Fact]
    public void DecisionMicrobenchmarkFiveRepetitions()
    {
        using var process = Process.GetCurrentProcess();
        for (int trial = 1; trial <= 5; trial++)
        {
            var correlator = new BehaviorWindowCorrelator(new UltronDecisionEngine());
            var timings = new double[500];
            TimeSpan cpu = process.TotalProcessorTime;
            for (int i = 0; i < timings.Length; i++)
            {
                long started = Stopwatch.GetTimestamp();
                var review = correlator.Observe(Event($"trial-{trial}-{i}", BehaviorObservationKind.FileWritten,
                    Actor(100 + i % 32), BehaviorAttribution.EtwThreadGeneration), Now);
                Assert.NotEqual(ProtectionActionKind.TerminateVerifiedActor, review.LongWindow.Recommendation);
                timings[i] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            }
            Array.Sort(timings); double p95 = timings[(int)(timings.Length * .95) - 1];
            output.WriteLine($"trial={trial}; p95_ms={p95:F3}; cpu_ms={(process.TotalProcessorTime - cpu).TotalMilliseconds:F1}; testhost_peak_bytes={process.PeakWorkingSet64}; synthetic_events=500");
            Assert.True(p95 <= 50, $"Synthetic p95 {p95:F3}ms exceeded review target; not a hardware/VM benchmark.");
        }
    }
}

