using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Benign fixtures verify real-time decisions without starting ETW or terminating processes.</summary>
public sealed class RealtimeReviewRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisRealtimeReview_" + Guid.NewGuid().ToString("N"));
    public RealtimeReviewRegressionTests() => Directory.CreateDirectory(_root);
    private string Fixture(string name)
    {
        var path = Path.GetFullPath(Path.Combine(_root, name));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "Harmless fixture content.");
        return path;
    }

    [Theory]
    [InlineData(90)]
    [InlineData(100)]
    public async Task HeuristicScoreNeverCreatesConfirmedRealtimeVerdict(int score)
    {
        var processor = new RealTimeVerdictProcessor(new HashService(), new Unsigned(), new FixedRisk(score));
        var result = await processor.InspectFileAsync(Fixture("benign.exe"));
        Assert.Equal(RealTimeVerdict.Suspicious, result.Verdict);
        Assert.Equal(RealTimePolicyAction.Warn, result.RecommendedPolicy);
    }

    [Fact]
    public async Task MissingFileIsUnknownRatherThanClean()
    {
        var processor = new RealTimeVerdictProcessor(new HashService(), new Unsigned(), new FixedRisk(0));
        var result = await processor.InspectFileAsync(Path.Combine(_root, "missing.exe"));
        Assert.Equal(RealTimeVerdict.Unknown, result.Verdict);
        Assert.Equal(RealTimePolicyAction.Observe, result.RecommendedPolicy);
    }

    [Theory]
    [InlineData("document.jpg")]
    [InlineData("readme.txt")]
    [InlineData("payload.unrecognized")]
    public async Task KnownHashCannotBeHiddenByExtension(string name)
    {
        const string testSignature = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        var processor = new RealTimeVerdictProcessor(new FixedHash(testSignature), new Unsigned(), new FixedRisk(0));
        var result = await processor.InspectFileAsync(Fixture(name));
        Assert.Equal(RealTimeVerdict.ConfirmedMalicious, result.Verdict);
    }

    [Fact]
    public async Task LockedMediaIsUnknownRatherThanAssumedSafe()
    {
        var path = Fixture("locked.jpg");
        using var locked = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var processor = new RealTimeVerdictProcessor(new HashService(), new Unsigned(), new FixedRisk(0));
        var result = await processor.InspectFileAsync(path);
        Assert.Equal(RealTimeVerdict.Unknown, result.Verdict);
    }

    [Theory]
    [InlineData("node_modules/payload.exe")]
    [InlineData(".git/payload.exe")]
    [InlineData("bin/Debug/payload.exe")]
    [InlineData("disguised.jpg")]
    [InlineData("payload")]
    public void ArrivalEventsAreNotExcludedByDeveloperDirectoryOrExtension(string name)
    {
        using var ingestor = new RealTimeEventIngestor(16);
        ingestor.EnqueueEvent(RealTimeEventType.Created, Fixture(name));
        Assert.Equal(1, ingestor.TotalAcceptedEvents);
        Assert.Equal(1, ingestor.PendingEventsCount);
    }

    [Theory]
    [InlineData("minecraft-mod.jar")]
    [InlineData("download.zip")]
    public void ExecutableArchivesReceiveCriticalArrivalPriorityWithoutAContentVerdict(string name)
    {
        using var ingestor = new RealTimeEventIngestor(8);
        ingestor.EnqueueEvent(RealTimeEventType.Created, Fixture(name));
        Assert.Equal(1, ingestor.PendingCriticalCount);
        Assert.Equal(0, ingestor.TotalProcessedEvents);
    }

    [Fact]
    public void CriticalFloodHasBoundedMemoryAndVisibleEventLoss()
    {
        using var ingestor = new RealTimeEventIngestor(8);
        for (int i = 0; i < 1000; i++)
            ingestor.EnqueueEvent(RealTimeEventType.Created, Path.Combine(_root, $"payload_{i}.exe"));
        Assert.InRange(ingestor.PendingCriticalCount, 1, 8);
        Assert.Equal(1000, ingestor.TotalAcceptedEvents + ingestor.TotalDroppedEvents);
        Assert.True(ingestor.TotalDroppedEvents > 0);
    }

    [Fact]
    public async Task RestartUsesOpenQueuesAndFreshWorkers()
    {
        using var ingestor = new RealTimeEventIngestor(8);
        var first = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ingestor.StartWorkers(1, (_, _) => { first.TrySetResult(); return Task.CompletedTask; }, CancellationToken.None);
        ingestor.EnqueueEvent(RealTimeEventType.Created, Path.Combine(_root, "one.exe"));
        await first.Task.WaitAsync(TimeSpan.FromSeconds(3));
        ingestor.Stop();
        var second = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ingestor.StartWorkers(1, (_, _) => { second.TrySetResult(); return Task.CompletedTask; }, CancellationToken.None);
        ingestor.EnqueueEvent(RealTimeEventType.Created, Path.Combine(_root, "two.exe"));
        await second.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(2, ingestor.TotalAcceptedEvents);
    }

    [Fact]
    public void EventsAfterStopAreNotReportedAsAccepted()
    {
        using var ingestor = new RealTimeEventIngestor(8);
        ingestor.Stop();
        ingestor.EnqueueEvent(RealTimeEventType.Created, Path.Combine(_root, "late.exe"));
        Assert.Equal(0, ingestor.TotalAcceptedEvents);
    }

    [Fact]
    public void FailedArrivalWorkerStartupDoesNotLeaveWatcherRunningWithoutConsumers()
    {
        var ingestor = new FailingStartIngestor();
        using var engine = new RealTimeProtectionEngine(ingestor, new Stable(),
            new VerdictStub(new RealTimeVerdictResult { Verdict = RealTimeVerdict.Unknown }), new FailedAction());
        engine.AddWatchDirectory(_root);

        Assert.Throws<IOException>(() => engine.Start(watchDefaultLocations: false));

        Assert.False(engine.IsRunning);
        Assert.Empty(engine.WatchedLocations);
        Assert.True(ingestor.StopCalled);
    }

    [Fact]
    public async Task FailedArrivalHandlerRequestsReconciliationInsteadOfSilentlyLosingCoverage()
    {
        using var ingestor = new RealTimeEventIngestor(8);
        string path = Fixture("handler-failure.exe");
        var reconciliation = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        ingestor.OnReconciliationRequired += affectedPath => reconciliation.TrySetResult(affectedPath);
        ingestor.StartWorkers(1, (_, _) => throw new IOException("Benign simulated inspection failure"), CancellationToken.None);

        ingestor.EnqueueEvent(RealTimeEventType.Created, path);

        Assert.Equal(path, await reconciliation.Task.WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.Equal(1, ingestor.TotalFailedEvents);
        Assert.Equal(0, ingestor.TotalProcessedEvents);
    }

    [Fact]
    public async Task EtwHeuristicScoreDoesNotSuspendOrBlockUnknownPid()
    {
        var hub = new FixedHub(new DetectionResult { RiskScore = 100, Verdict = DetectionVerdict.HighRisk, IsComplete = true });
        using var service = new EtwPreExecProtectionService(hub, new FixedRisk(100), new Unsigned());
        var result = await service.EvaluateProcessAsync(int.MaxValue, Fixture("untrusted.exe"));
        Assert.False(result.WasSuspended);
        Assert.False(result.WasBlocked);
        Assert.Contains("unconfirmed", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EtwIncompleteAnalysisNeverReportsCleanExecution()
    {
        var hub = new FixedHub(new DetectionResult { Verdict = DetectionVerdict.Unknown, IsComplete = false, FailedDetectorCount = 1 });
        using var service = new EtwPreExecProtectionService(hub, new FixedRisk(0), new Unsigned());
        var result = await service.EvaluateProcessAsync(int.MaxValue, Fixture("incomplete.exe"));
        Assert.False(result.WasBlocked);
        Assert.Contains("incomplete", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(DetectionVerdict.HighRisk, true, RealTimeVerdict.Suspicious, RealTimePolicyAction.Warn)]
    [InlineData(DetectionVerdict.Unknown, false, RealTimeVerdict.Unknown, RealTimePolicyAction.Observe)]
    public async Task RealtimeUsesSharedDetectionPipelineAndPreservesIncompleteVerdicts(DetectionVerdict detected, bool complete, RealTimeVerdict expected, RealTimePolicyAction policy)
    {
        var hub = new FixedHub(new DetectionResult { Verdict = detected, IsComplete = complete, RiskScore = complete ? 95 : 0 });
        var processor = new RealTimeVerdictProcessor(new HashService(), new Unsigned(), new FixedRisk(0),
            null, null, null, detectionHub: hub);
        var result = await processor.InspectFileAsync(Fixture("hub_input.jpg"));
        Assert.Equal(expected, result.Verdict);
        Assert.Equal(policy, result.RecommendedPolicy);
        Assert.Equal(1, hub.EvaluationCount);
        Assert.NotNull(hub.LastContext?.SharedScan);
        Assert.Equal(result.SHA256, hub.LastContext!.SHA256);
    }

    [Fact]
    public async Task RealtimeAcceptsExactSharedDetectionEvidenceWithoutHeuristicPromotion()
    {
        var detection = new DetectionResult { Verdict = DetectionVerdict.ConfirmedMalicious, RiskScore = 100 };
        detection.Evidences.Add(new SecurityEvidence { Category = EvidenceCategory.StaticSignature, Confidence = EvidenceConfidence.Absolute, ScoreContribution = 100 });
        var processor = new RealTimeVerdictProcessor(new HashService(), new Unsigned(), new FixedRisk(0),
            null, null, null, detectionHub: new FixedHub(detection));
        var result = await processor.InspectFileAsync(Fixture("hub_exact.exe"));
        Assert.Equal(RealTimeVerdict.ConfirmedMalicious, result.Verdict);
        Assert.Equal(RealTimePolicyAction.BlockAndQuarantine, result.RecommendedPolicy);
    }

    [Fact]
    public void DuplicateArrivalsAreBoundedButWritesAfterConsumptionRemainEligible()
    {
        using var ingestor = new RealTimeEventIngestor(8);
        string path = Fixture("repeat.exe");
        for (int i = 0; i < 1000; i++) ingestor.EnqueueEvent(RealTimeEventType.Modified, path);
        Assert.Equal(1, ingestor.PendingEventsCount);
        Assert.Equal(999, ingestor.TotalCoalescedEvents);
        Assert.Equal(0, ingestor.TotalDroppedEvents);
    }

    [Fact]
    public async Task QuarantineEnforcerRejectsUnconfirmedHighScore()
    {
        var vault = new RecordingVault();
        var enforcer = new RealTimePolicyEnforcer(vault, new Findings());
        string path = Fixture("heuristic.exe");
        bool acted = await enforcer.EnforceQuarantineWithOutcomeAsync(new NormalizedFileEvent { NormalizedPath = path },
            new RealTimeVerdictResult { Verdict = RealTimeVerdict.Suspicious, RiskScore = 100,
                SHA256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))), RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine }, CancellationToken.None);
        Assert.False(acted);
        Assert.Equal(0, vault.AutomaticCalls);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task QuarantineEnforcerHonorsDisabledAutomaticPolicy()
    {
        var vault = new RecordingVault();
        var enforcer = new RealTimePolicyEnforcer(vault, new Findings(), enableAutoQuarantine: () => false);
        string path = Fixture("disabled.exe");
        bool acted = await enforcer.EnforceQuarantineWithOutcomeAsync(new NormalizedFileEvent { NormalizedPath = path }, Confirmed(path), CancellationToken.None);
        Assert.False(acted);
        Assert.Equal(0, vault.AutomaticCalls);
    }

    [Fact]
    public async Task QuarantineEnforcerCannotApplyStaleVerdictToReplacedContent()
    {
        var vault = new RecordingVault();
        var enforcer = new RealTimePolicyEnforcer(vault, new Findings());
        string path = Fixture("changed.exe");
        var verdict = Confirmed(path);
        File.WriteAllText(path, "A different benign document version.");
        bool acted = await enforcer.EnforceQuarantineWithOutcomeAsync(new NormalizedFileEvent { NormalizedPath = path }, verdict, CancellationToken.None);
        Assert.False(acted);
        Assert.True(File.Exists(path));
        Assert.Equal("A different benign document version.", File.ReadAllText(path));
    }

    [Fact]
    public async Task EtwDisabledPolicyDoesNotRequestAutomaticActionForExactEvidence()
    {
        var result = new DetectionResult { Verdict = DetectionVerdict.ConfirmedMalicious, RiskScore = 100 };
        result.Evidences.Add(new SecurityEvidence { Category = EvidenceCategory.StaticSignature, Confidence = EvidenceConfidence.Absolute, ScoreContribution = 100 });
        var vault = new RecordingVault();
        using var service = new EtwPreExecProtectionService(new FixedHub(result), new FixedRisk(0), new Unsigned(),
            quarantineService: vault, enableAutoQuarantine: () => false);
        var decision = await service.EvaluateProcessAsync(int.MaxValue, Fixture("etw_disabled.exe"));
        Assert.False(decision.WasBlocked);
        Assert.Equal(0, vault.AutomaticCalls);
    }

    [Fact]
    public async Task EtwCriticalNameDoesNotBypassContentInspection()
    {
        var hub = new FixedHub(new DetectionResult { Verdict = DetectionVerdict.HighRisk, RiskScore = 95 });
        using var service = new EtwPreExecProtectionService(hub, new FixedRisk(0), new Unsigned());
        var decision = await service.EvaluateProcessAsync(int.MaxValue, Fixture("svchost.exe"));
        Assert.False(decision.Whitelisted);
        Assert.False(decision.WasSuspended);
        Assert.Equal(95, decision.RiskScore);
    }

    [Theory]
    [InlineData(RealTimeVerdict.Unknown, RealTimePolicyAction.Observe, "OBSERVED_UNVERIFIED")]
    [InlineData(RealTimeVerdict.ConfirmedMalicious, RealTimePolicyAction.BlockAndQuarantine, "QUARANTINE_UNCONFIRMED")]
    public async Task ActualWatcherPipelineDoesNotClaimCleanOrSuccessfulActionWithoutEvidence(RealTimeVerdict verdict, RealTimePolicyAction policy, string expectedAction)
    {
        var observed = new TaskCompletionSource<RealTimeActivityEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var engine = new RealTimeProtectionEngine(new RealTimeEventIngestor(8), new Stable(),
            new VerdictStub(new RealTimeVerdictResult { Verdict = verdict, RecommendedPolicy = policy }), new FailedAction());
        engine.OnActivityLogged += evt => { if (evt.Stage == "ACTION_APPLIED") observed.TrySetResult(evt); };
        engine.Start(watchDefaultLocations: false);
        engine.AddWatchDirectory(_root);
        Fixture("arrival.exe");
        var activity = await observed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(expectedAction, activity.Action);
        Assert.NotEqual("Success", activity.Severity);
    }

    private static RealTimeVerdictResult Confirmed(string path) => new()
    {
        Verdict = RealTimeVerdict.ConfirmedMalicious, RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine,
        SHA256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))), RiskScore = 100, RiskLevel = RiskLevel.ConfirmedMalicious
    };

    [Fact]
    public async Task MovingPopulatedDirectoryIntoWatchedRootInspectsExistingChildren()
    {
        string source = Path.Combine(_root, "outside");
        string watched = Path.Combine(_root, "watched");
        Directory.CreateDirectory(source);
        Directory.CreateDirectory(watched);
        File.WriteAllText(Path.Combine(source, "existing.exe"), "Benign moved fixture.");
        var observed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var engine = new RealTimeProtectionEngine(new RealTimeEventIngestor(32), new Stable(),
            new VerdictStub(new RealTimeVerdictResult { Verdict = RealTimeVerdict.Unknown, RecommendedPolicy = RealTimePolicyAction.Observe }), new FailedAction());
        engine.OnActivityLogged += evt => { if (evt.Stage == "VERDICT" && evt.FileName == "existing.exe") observed.TrySetResult(evt.FilePath); };
        engine.Start(watchDefaultLocations: false);
        engine.AddWatchDirectory(watched);
        string moved = Path.Combine(watched, "arrived");
        Directory.Move(source, moved);
        string inspectedPath = await observed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(Path.Combine(moved, "existing.exe"), inspectedPath);
    }

    public void Dispose() => Directory.Delete(_root, true);

    private sealed class FixedHash(string hash) : IHashService
    {
        public Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken = default) => Task.FromResult(hash);
        public Task<string> ComputeSha1Async(string path, CancellationToken cancellationToken = default) => Task.FromResult(string.Empty);
    }
    private sealed class FixedRisk(int score) : IRiskScoringEngine
    {
        public Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(FileAnalysisResult result, CancellationToken cancellationToken = default)
            => Task.FromResult((score, score >= 70 ? RiskLevel.HighRisk : RiskLevel.Clean, new List<string> { "Synthetic heuristic evidence only" }));
    }
    private sealed class Unsigned : ISignatureVerifier
    {
        public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default) => Task.FromResult(new SignatureInfo());
    }
    private sealed class FixedHub(DetectionResult result) : IDetectionHub
    {
        public int EvaluationCount { get; private set; }
        public DetectionContext? LastContext { get; private set; }
        public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            EvaluationCount++;
            LastContext = context;
            return Task.FromResult(result);
        }
        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => Array.Empty<IDetectorPlugin>();
        public void RegisterDetector(IDetectorPlugin detector) { }
        public bool UnregisterDetector(string detectorId) => false;
    }

    private sealed class Findings : ISecurityFindingService
    {
        public Task AddFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task UpdateFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<List<SecurityFinding>> GetAllFindingsAsync(CancellationToken cancellationToken = default) => Task.FromResult(new List<SecurityFinding>());
        public Task<List<SecurityFinding>> GetFindingsByRiskAsync(RiskLevel riskLevel, CancellationToken cancellationToken = default) => GetAllFindingsAsync(cancellationToken);
        public Task<SecurityFinding?> GetFindingByIdAsync(Guid id, CancellationToken cancellationToken = default) => Task.FromResult<SecurityFinding?>(null);
        public Task<int> GetActiveCountAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);
    }
    private sealed class RecordingVault : IQuarantineService, IContentBoundQuarantineService
    {
        public int AutomaticCalls { get; private set; }
        public string? LastError => null;
        public event Action<QuarantineEntry>? OnFileQuarantined { add { } remove { } }
        public event Action<int>? OnFileRestored { add { } remove { } }
        public event Action<int>? OnFileDeleted { add { } remove { } }
        public Task<bool> TryQuarantineFileAsync(string path, string reason, string expectedSha256, CancellationToken cancellationToken = default)
        {
            AutomaticCalls++;
            return Task.FromResult(string.Equals(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))), expectedSha256, StringComparison.OrdinalIgnoreCase));
        }
        public Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken = default) => throw new InvalidOperationException("Unbound action must never be used.");
        public Task<bool> RestoreFileAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<bool> RestoreFileAsync(int id, string? customDestinationPath, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default) => Task.FromResult(new List<QuarantineEntry>());
        public Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult<QuarantineEntry?>(null);
    }
    private sealed class Stable : IRealTimeStabilityChecker
    { public Task<bool> WaitForFileStabilityAsync(string filePath, CancellationToken ct) => Task.FromResult(true); }
    private sealed class VerdictStub(RealTimeVerdictResult result) : IRealTimeVerdictProcessor
    {
        public Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default) => Task.FromResult(result);
        public void CleanupCache() { }
    }
    private sealed class FailedAction : IRealTimePolicyEnforcer, IRealTimePolicyOutcomeEnforcer
    {
        public event Action<SecurityFinding>? OnThreatDetected { add { } remove { } }
        public event Action<SecurityIncident>? OnIncidentCreated { add { } remove { } }
        public event Action<string, string, string>? OnNotificationRaised { add { } remove { } }
        public Task EnforceWarningAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct) => Task.CompletedTask;
        public Task EnforceQuarantineAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct) => Task.CompletedTask;
        public Task<bool> EnforceQuarantineWithOutcomeAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct) => Task.FromResult(false);
    }

    private sealed class FailingStartIngestor : IRealTimeEventIngestor
    {
        public bool StopCalled { get; private set; }
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
        public void EnqueueEvent(RealTimeEventType type, string path, string? oldPath = null) { }
        public void StartWorkers(int workerCount, Func<NormalizedFileEvent, CancellationToken, Task> eventHandler, CancellationToken ct) =>
            throw new IOException("Benign simulated arrival worker startup failure");
        public void Stop() => StopCalled = true;
        public void Dispose() { }
    }
}
