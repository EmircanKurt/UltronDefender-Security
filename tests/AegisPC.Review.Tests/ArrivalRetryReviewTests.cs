using System.IO;
using System.Text;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Exercises benign file arrivals through the real engine with inert event delivery and no containment.</summary>
public sealed class ArrivalRetryReviewTests
{
    /// <summary>A shared writer must close before the actual stability checker permits content inspection.</summary>
    [Fact]
    public async Task ActiveWriter_IsNotMistakenForStableReadableContent()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("Harmless writer stability fixture."));
        var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        try
        {
            var pending = new RealTimeStabilityChecker().WaitForFileStabilityAsync(path, CancellationToken.None);
            await Task.Delay(160);
            Assert.False(pending.IsCompleted);
            writer.Dispose();
            Assert.True(await pending.WaitAsync(TimeSpan.FromSeconds(3)));
        }
        finally { writer.Dispose(); }
    }

    /// <summary>A transient result is retried without needing a second filesystem event; partial content is not retried.</summary>
    [Theory]
    [InlineData(true, 2, false)]
    [InlineData(false, 1, true)]
    public async Task Arrival_RetriesOnlyTypedTransientFailure(bool transient, int expectedCalls, bool expectedGap)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("Harmless arrival retry fixture."));
        var processor = new FixtureVerdict(transient);
        var arrivals = new InertArrivals();
        using var engine = new RealTimeProtectionEngine(arrivals, new Stable(), processor, new NoAction());
        engine.Start(watchDefaultLocations: false);
        await arrivals.DeliverAsync(path).WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(expectedCalls, processor.Calls);
        Assert.Equal(expectedGap, engine.CaptureCoverage().HasPersistentGap);
        Assert.False(engine.CaptureCoverage().RecoveryPending);
        // A later complete inspection clears this file's gap, not unrelated watcher/queue loss.
        await arrivals.DeliverAsync(path);
        Assert.False(engine.CaptureCoverage().HasPersistentGap);
    }

    private sealed class FixtureVerdict(bool transient) : IRealTimeVerdictProcessor
    {
        internal int Calls;
        public Task<RealTimeVerdictResult> InspectFileAsync(string path, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            int call = ++Calls;
            return Task.FromResult(call == 1
                ? new RealTimeVerdictResult { Retryable = transient, RecommendedPolicy = RealTimePolicyAction.Observe,
                    CoverageLimitations = [transient ? "SyntheticSharingFailure" : "UnsupportedInspection"] }
                : new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean, InspectionComplete = true,
                    RecommendedPolicy = RealTimePolicyAction.Allow });
        }
        public void CleanupCache() { }
    }

    private sealed class Stable : IRealTimeStabilityChecker
    {
        public Task<bool> WaitForFileStabilityAsync(string path, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return Task.FromResult(true); }
    }

    private sealed class NoAction : IRealTimePolicyEnforcer
    {
        public event Action<SecurityFinding>? OnThreatDetected { add { } remove { } }
        public event Action<SecurityIncident>? OnIncidentCreated { add { } remove { } }
        public event Action<string, string, string>? OnNotificationRaised { add { } remove { } }
        public Task EnforceWarningAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct)
            => throw new InvalidOperationException("No intervention belongs to benign retry fixtures.");
        public Task EnforceQuarantineAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct)
            => throw new InvalidOperationException("No intervention belongs to benign retry fixtures.");
    }

    private sealed class InertArrivals : IRealTimeEventIngestor
    {
        private Func<NormalizedFileEvent, CancellationToken, Task>? _handler;
        private CancellationToken _token;
        public long TotalProducedEvents => 0;
        public long TotalAcceptedEvents => 0;
        public long TotalProcessedEvents => 0;
        public long TotalDroppedEvents => 0;
        public long TotalFailedEvents => 0;
        public long TotalEnqueuedEvents => 0;
        public long DroppedEventsCount => 0;
        public int PendingEventsCount => 0;
        public int PendingCriticalCount => 0;
        public int PendingTelemetryCount => 0;
        public void EnqueueEvent(RealTimeEventType type, string path, string? oldPath = null) => throw new NotSupportedException();
        public void StartWorkers(int workers, Func<NormalizedFileEvent, CancellationToken, Task> handler, CancellationToken ct)
        { _handler = handler; _token = ct; }
        internal Task DeliverAsync(string path) => (_handler ?? throw new InvalidOperationException())(
            new NormalizedFileEvent { FilePath = path, NormalizedPath = path, EventType = RealTimeEventType.Modified }, _token);
        public void Stop() => _handler = null;
        public void Dispose() => Stop();
    }
}
