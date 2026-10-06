using System.IO;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Exercises real benign file I/O with inert detection and arrival dependencies; no OS watcher or action is started.</summary>
public sealed class RealtimeRevisionAuditReviewTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "UltronRealtimeRevisionAudit-" + Guid.NewGuid().ToString("N"));

    /// <summary>Creates a unique temporary fixture root, without using installed protection or user files.</summary>
    public RealtimeRevisionAuditReviewTests() => Directory.CreateDirectory(_root);

    /// <summary>A policy change during either analysis route prevents that completed old result from entering the new policy's cache.</summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(true, false)]
    public async Task CompletedRealtimeAnalysis_UsesCapturedCacheRevision(bool useHub, bool invalidateDuringAnalysis)
    {
        string path = await FixtureAsync();
        var matcher = new FileHashMatcher(new HashService(), new Unsigned(), null!);
        Action duringAnalysis = () => { if (invalidateDuringAnalysis) DetectionPolicyRevision.Invalidate(); };
        var processor = new RealTimeVerdictProcessor(new HashService(), new Unsigned(),
            new FixtureRisk(useHub ? () => { } : duringAnalysis), matcher, null, null,
            detectionHub: useHub ? new FixtureHub(duringAnalysis) : null);

        var verdict = await processor.InspectFileAsync(path);
        var cached = await matcher.TryGetCachedAsync(path, new FileInfo(path), CancellationToken.None);

        Assert.Equal(RealTimeVerdict.Clean, verdict.Verdict);
        Assert.True(verdict.InspectionComplete);
        Assert.Equal(!invalidateDuringAnalysis, cached.Hit);
        Assert.Equal(invalidateDuringAnalysis ? 0 : 1, matcher.CachedEntriesCount);
    }

    /// <summary>Normal arrival callbacks retain incomplete inspection as a coverage gap and never display an unverified file as allowed.</summary>
    [Theory]
    [InlineData(RealTimeVerdict.Unknown, true, false, true)]
    [InlineData(RealTimeVerdict.Clean, false, false, true)]
    [InlineData(RealTimeVerdict.Clean, true, true, true)]
    [InlineData(RealTimeVerdict.Clean, true, false, false)]
    public async Task NormalArrival_PreservesInspectionCoverage(RealTimeVerdict verdict, bool inspectionComplete,
        bool partialClassification, bool expectedGap)
    {
        string path = await FixtureAsync();
        var outcome = new RealTimeVerdictResult
        {
            Verdict = verdict,
            RecommendedPolicy = verdict == RealTimeVerdict.Unknown ? RealTimePolicyAction.Observe : RealTimePolicyAction.Allow,
            InspectionComplete = inspectionComplete,
            ContentClassification = partialClassification
                ? new FileContentClassification { Coverage = ContentClassificationCoverage.Partial } : null
        };
        var arrivals = new InertArrivals();
        using var engine = new RealTimeProtectionEngine(arrivals, new Stable(),
            new FixtureVerdict((_, _) => Task.FromResult(outcome)), new NoAction());
        string? action = null;
        engine.OnActivityLogged += activity => { if (activity.Stage == "ACTION_APPLIED") action = activity.Action; };
        engine.Start(watchDefaultLocations: false);
        Assert.False(engine.CaptureCoverage().HasPersistentGap);

        await arrivals.DeliverAsync(path);

        Assert.Equal(expectedGap, engine.CaptureCoverage().HasPersistentGap);
        Assert.Equal(expectedGap ? "OBSERVED_UNVERIFIED" : "ALLOWED", action);
        Assert.Empty(engine.WatchedLocations);
    }

    /// <summary>An incomplete response that finishes after its cancelled engine generation cannot mark the restarted engine degraded.</summary>
    [Fact]
    public async Task OldArrivalGeneration_DoesNotMarkReplacementCoverageDegraded()
    {
        string path = await FixtureAsync();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<RealTimeVerdictResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var arrivals = new InertArrivals();
        using var engine = new RealTimeProtectionEngine(arrivals, new Stable(), new FixtureVerdict(async (_, _) =>
        {
            entered.TrySetResult();
            return await release.Task;
        }), new NoAction());
        int terminalActivities = 0;
        engine.OnActivityLogged += activity => { if (activity.Stage == "ACTION_APPLIED") terminalActivities++; };
        engine.Start(watchDefaultLocations: false);
        var oldArrival = arrivals.DeliverAsync(path);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        engine.Stop();
        engine.Start(watchDefaultLocations: false);

        release.TrySetResult(new RealTimeVerdictResult { Verdict = RealTimeVerdict.Unknown,
            RecommendedPolicy = RealTimePolicyAction.Observe });
        await oldArrival.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(engine.CaptureCoverage().HasPersistentGap);
        Assert.Equal(0, terminalActivities);
        Assert.True(engine.IsRunning);
        Assert.Empty(engine.WatchedLocations);
    }

    private async Task<string> FixtureAsync()
    {
        string path = Path.Combine(_root, "fixture.txt");
        await File.WriteAllTextAsync(path, "Harmless real-time policy and coverage review fixture.");
        return path;
    }

    /// <summary>Removes only this test instance's unique temporary fixture root after inert dependencies are disposed.</summary>
    public void Dispose() => Directory.Delete(_root, recursive: true);

    private sealed class Unsigned : ISignatureVerifier
    {
        public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default)
            => Task.FromResult(new SignatureInfo());
    }

    private sealed class FixtureRisk(Action duringAnalysis) : IRiskScoringEngine
    {
        public Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(FileAnalysisResult result,
            CancellationToken cancellationToken = default)
        {
            duringAnalysis();
            return Task.FromResult((0, RiskLevel.Clean, new List<string>()));
        }
    }

    private sealed class FixtureHub(Action duringAnalysis) : IDetectionHub
    {
        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => [];
        public void RegisterDetector(IDetectorPlugin detector) => throw new NotSupportedException();
        public bool UnregisterDetector(string detectorId) => false;
        public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            duringAnalysis();
            return Task.FromResult(new DetectionResult { Verdict = DetectionVerdict.Clean, IsComplete = true });
        }
    }

    private sealed class Stable : IRealTimeStabilityChecker
    {
        public Task<bool> WaitForFileStabilityAsync(string filePath, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return Task.FromResult(true); }
    }

    private sealed class FixtureVerdict(Func<string, CancellationToken, Task<RealTimeVerdictResult>> inspect) : IRealTimeVerdictProcessor
    {
        public Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default) => inspect(filePath, ct);
        public void CleanupCache() { }
    }

    private sealed class NoAction : IRealTimePolicyEnforcer
    {
        public event Action<SecurityFinding>? OnThreatDetected { add { } remove { } }
        public event Action<SecurityIncident>? OnIncidentCreated { add { } remove { } }
        public event Action<string, string, string>? OnNotificationRaised { add { } remove { } }
        public Task EnforceWarningAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct) => Task.CompletedTask;
        public Task EnforceQuarantineAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct)
            => throw new InvalidOperationException("No quarantine action belongs to these benign fixtures.");
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
        public void StartWorkers(int workerCount, Func<NormalizedFileEvent, CancellationToken, Task> eventHandler, CancellationToken ct)
        { _handler = eventHandler; _token = ct; }
        internal Task DeliverAsync(string path) => (_handler ?? throw new InvalidOperationException())(
            new NormalizedFileEvent { FilePath = path, NormalizedPath = path, EventType = RealTimeEventType.Modified }, _token);
        public void Stop() => _handler = null;
        public void Dispose() => Stop();
    }
}
