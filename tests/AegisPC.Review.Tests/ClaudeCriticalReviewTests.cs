using System.Diagnostics;
using System.IO;
using System.Text;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Protection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Exceptions;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using AegisPC.Security.UltronAI;
using AegisPC.Service.IPC;
using AegisPC.ServiceContracts.IpcMessages;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Benign disk fixtures and inert action adapters; never starts a service, ETW session or native intervention.</summary>
public sealed class ClaudeCriticalReviewTests
{
    /// <summary>Incomplete coverage must not erase a positive review signal or grant containment authority.</summary>
    [Theory]
    [InlineData(50)]
    [InlineData(70)]
    [InlineData(80)]
    public async Task PartialPositive_RemainsSuspiciousNotUnknown(int score)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("benign.txt", Encoding.UTF8.GetBytes("Benign partial-inspection fixture."));
        var hub = new FixedHub(new DetectionResult { Verdict = DetectionVerdict.Suspicious, RiskScore = score,
            IsComplete = false, FailedDetectorCount = 1, CoverageLimitations = ["SyntheticBudgetExceeded"] });
        var result = await Processor(fixture, hub).InspectFileAsync(path);
        Assert.Equal(RealTimeVerdict.Suspicious, result.Verdict);
        Assert.Equal(RealTimePolicyAction.Warn, result.RecommendedPolicy);
        Assert.False(result.InspectionComplete);
        Assert.Equal(score, result.RiskScore);
        Assert.Contains("SyntheticBudgetExceeded", result.CoverageLimitations);
        Assert.Contains("Inspection incomplete", result.ThreatDescription);
    }

    [Theory]
    [InlineData(80)]
    [InlineData(81)]
    [InlineData(82)]
    [InlineData(83)]
    [InlineData(84)]
    /// <summary>Inert confirmed outcomes preserve 80–84 decisions and require intent before an attempted action.</summary>
    public async Task ExactVerdict_NumericPreferenceDoesNotDowngradeAndIntentPrecedesAction(int score)
    {
        var audit = new FakeAuditLogService();
        var findings = new SecurityFindingService();
        var vault = new InertVault(() => Assert.Contains(audit.Entries, e => e.Result == AuditResult.Pending));
        var enforcer = new RealTimePolicyEnforcer(vault, findings, audit, enableAutoQuarantine: () => true,
            autoQuarantineThreshold: () => 100);
        SecurityIncident? incident = null;
        enforcer.OnIncidentCreated += value => incident = value;
        bool result = await enforcer.EnforceQuarantineWithOutcomeAsync(new() { NormalizedPath = "inert-fixture-only.bin" },
            new() { Verdict = RealTimeVerdict.ConfirmedMalicious, RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine,
                SHA256 = new string('A', 64), RiskScore = score, RiskLevel = RiskLevel.ConfirmedMalicious }, default);
        Assert.True(result); Assert.Equal(1, vault.Calls);
        Assert.Equal(2, audit.Entries.Count);
        Assert.Equal(AuditResult.Pending, audit.Entries[0].Result);
        Assert.Equal(AuditResult.Success, audit.Entries[1].Result);
        Assert.Single(await findings.GetAllFindingsAsync());
        Assert.Equal(0, incident!.RootPid);
        Assert.Contains("kalıcılık", incident.ActionTaken);
        Assert.DoesNotContain("etkisiz", incident.ActionTaken);
    }

    [Fact]
    /// <summary>A failed pending audit prevents the inert executor from being invoked.</summary>
    public async Task IntentWriteFailure_PreventsAction()
    {
        var vault = new InertVault(() => { });
        var enforcer = new RealTimePolicyEnforcer(vault, new SecurityFindingService(), new FailingAudit());
        Assert.False(await enforcer.EnforceQuarantineWithOutcomeAsync(new() { NormalizedPath = "inert.bin" },
            new() { Verdict = RealTimeVerdict.ConfirmedMalicious, RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine,
                SHA256 = new string('A', 64), RiskScore = 100 }, default));
        Assert.Equal(0, vault.Calls);
    }

    [Theory]
    [InlineData(ServiceCommandType.QuarantineFile, true)]
    [InlineData(ServiceCommandType.RestoreQuarantine, true)]
    [InlineData(ServiceCommandType.DeleteQuarantine, true)]
    [InlineData(ServiceCommandType.GetQuarantine, false)]
    [InlineData(ServiceCommandType.GetQuarantineItem, false)]
    /// <summary>The current read-only pilot cannot mutate the vault merely by presenting the same user's SID.</summary>
    public void ReadOnlyVaultTransport_DeniesAllMutationKinds(ServiceCommandType command, bool expected)
        => Assert.Equal(expected, VaultMutationPilotPolicy.RequiresAuthenticatedApproval(command));

    [Theory]
    [InlineData(OperatingSystemFileBlockKind.ThreatBlocked)]
    [InlineData(OperatingSystemFileBlockKind.ThreatRemoved)]
    /// <summary>An injected OS access result remains unavailable inspection, not a malware-family claim.</summary>
    public async Task OsAccessBlock_IsUnknownNotUltronConfirmation(OperatingSystemFileBlockKind kind)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("ordinary.txt", Encoding.UTF8.GetBytes("Benign typed failure fixture."));
        var hub = new FixedHub(new DetectionResult());
        var processor = new RealTimeVerdictProcessor(new BlockedHash(kind), fixture.SignatureVerifier,
            new ZeroRisk(), null, null, null, detectionHub: hub);
        var result = await processor.InspectFileAsync(path);
        Assert.Equal(RealTimeVerdict.Unknown, result.Verdict);
        Assert.Equal(RealTimePolicyAction.Observe, result.RecommendedPolicy);
        Assert.Equal(kind, result.OperatingSystemBlock);
        Assert.Empty(result.SHA256); Assert.False(result.InspectionComplete);
        Assert.DoesNotContain("EICAR", result.ThreatTitle);
        Assert.Equal(0, hub.Calls);
    }

    [Theory]
    [InlineData(unchecked((int)0x800700E1), true)]
    [InlineData(unchecked((int)0x800700E2), true)]
    [InlineData(unchecked((int)0x80070005), false)]
    /// <summary>Only documented native codes, never localized message substrings, establish an OS security block.</summary>
    public void OsBlock_RequiresDocumentedCodeNotVirusMessage(int code, bool expected)
        => Assert.Equal(expected, OperatingSystemFileBlockException.TryGetKind(new CodedIo(code), out _));

    [Theory]
    [InlineData(OperatingSystemFileBlockKind.ThreatBlocked)]
    [InlineData(OperatingSystemFileBlockKind.ThreatRemoved)]
    /// <summary>The manual pipeline also retains typed OS failures without fake EICAR findings or source removal.</summary>
    public async Task ManualOsBlock_IsPartialWithoutFakeHashOrFinding(OperatingSystemFileBlockKind kind)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("ordinary.txt", Encoding.UTF8.GetBytes("Benign manual error fixture."));
        using var resources = new AdaptiveScanResourceManager(storageClassifier: _ => true,
            pressureSampler: () => (50, 10, false), enableTelemetryTimer: false, workloadSampler: () => (5, 1));
        using var queue = new ScanQueueCoordinator(resources);
        var scanner = new FileScannerService(new DirectoryWalker(), queue,
            new FileHashMatcher(new BlockedHash(kind), fixture.SignatureVerifier, null!),
            new PupAnalysisCoordinator(new FixedHub(new DetectionResult())), new ArchiveSafetyScanner());
        var result = await scanner.ScanFileDetailedAsync(path, TimeSpan.FromSeconds(5));
        Assert.Equal(FileScanOutcome.Failed, result.Outcome);
        Assert.Equal(kind, result.OperatingSystemBlock);
        Assert.False(result.InspectionComplete); Assert.Null(result.Finding);
        Assert.True(File.Exists(path));
    }

    [Fact]
    /// <summary>No detector means unavailable coverage; a completed empty detector means only no observed findings.</summary>
    public async Task NoEvidence_IsLowConfidenceNoFindingsRatherThanSafetyCertificate()
    {
        var hub = new AegisPC.Security.Detection.DetectionHub();
        var missing = await hub.EvaluateAsync(new DetectionContext());
        Assert.Equal(DetectionVerdict.Unknown, missing.Verdict);
        Assert.Equal("İnceleme tamamlanamadı", missing.ThreatTitle);
        hub.RegisterDetector(new EmptyDetector());
        var result = await hub.EvaluateAsync(new DetectionContext());
        Assert.Equal(EvidenceConfidence.Low, result.OverallConfidence);
        Assert.Equal("İncelenen kapsamda bulgu yok", result.ThreatTitle);
    }

    [Fact]
    /// <summary>The real production vault rejects unbrokered automatic containment, preserving owned benign bytes.</summary>
    public async Task ProductionAutomaticGate_PreservesBenignSourceAndVault()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("preserved.txt", Encoding.UTF8.GetBytes("Never contain this benign pilot fixture."));
        string hash = await fixture.HashService.ComputeSha256Async(path);
        using var vault = new QuarantineService(fixture.HashService, customVaultDir: fixture.VaultDirectory,
            signatureVerifier: fixture.SignatureVerifier);
        Assert.False(ProtectionNativePilotPolicy.AutomaticContainmentAvailable);
        Assert.False(await vault.TryQuarantineFileAsync(path, "inert proof", hash));
        Assert.Equal(ProtectionNativePilotPolicy.ReasonCode, vault.LastError);
        Assert.True(File.Exists(path));
        Assert.Equal(hash, await fixture.HashService.ComputeSha256Async(path));
        Assert.Empty(await vault.GetQuarantinedItemsAsync());
    }

    [Fact]
    /// <summary>Same size and restored timestamp cannot make changed benign contents reuse a cached verdict.</summary>
    public async Task Cache_RehashesSameLengthAndRestoredTimestamp()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("identity.txt", Encoding.ASCII.GetBytes("same length A"));
        var info = new FileInfo(path); DateTime stamp = info.LastWriteTimeUtc;
        string hash = await fixture.HashService.ComputeSha256Async(path);
        var matcher = new FileHashMatcher(fixture.HashService, fixture.SignatureVerifier, null!);
        matcher.SetCache(path, info.Length, stamp, null, hash, false, false);
        Assert.True((await matcher.TryGetCachedAsync(path, new FileInfo(path), default)).Hit);
        File.WriteAllBytes(path, Encoding.ASCII.GetBytes("same length B"));
        File.SetLastWriteTimeUtc(path, stamp);
        var cached = await matcher.TryGetCachedAsync(path, new FileInfo(path), default);
        Assert.False(cached.Hit); Assert.NotEqual(hash, cached.VerifiedHash);
    }

    [Fact]
    /// <summary>One actor's loss does not poison unrelated observations or invalid samples, and expires with the window.</summary>
    public void Correlator_LossIsActorScopedAndRecoversAfterWindow()
    {
        var now = DateTimeOffset.UtcNow;
        var correlator = new BehaviorWindowCorrelator(new UltronDecisionEngine());
        var actor = new BehaviorProcessIdentity(100, now.AddMinutes(-1), "test-boot");
        BehaviorWindowReview? review = null;
        for (int i = 0; i < 65; i++) review = correlator.Observe(Observation(i.ToString(), actor, now), now);
        Assert.False(review!.AttributionComplete);
        Assert.True(correlator.Observe(Observation("other", actor with { Pid = 101 }, now), now).AttributionComplete);
        Assert.True(correlator.Observe(Observation("later", actor, now.AddMinutes(6)), now.AddMinutes(6)).AttributionComplete);
        int samples = correlator.Statistics.Count;
        var invalid = correlator.Observe(Observation("invalid", actor with { Pid = 0 }, now), now);
        Assert.Null(invalid.Actor); Assert.Equal(samples, correlator.Statistics.Count);
    }

    [Fact]
    /// <summary>Bounded tombstones retain missing history when an evicted actor returns; explicit clearing resets current scope.</summary>
    public void Correlator_EvictedActorDoesNotReappearWithInventedCompleteHistory()
    {
        var now = DateTimeOffset.UtcNow;
        var correlator = new BehaviorWindowCorrelator(new UltronDecisionEngine());
        var first = new BehaviorProcessIdentity(100, now.AddMinutes(-1), "test-boot");
        for (int i = 0; i < 513; i++) correlator.Observe(Observation(i.ToString(), first with { Pid = 100 + i }, now.AddMilliseconds(i)), now.AddSeconds(1));
        Assert.False(correlator.Observe(Observation("returned", first, now.AddSeconds(2)), now.AddSeconds(2)).AttributionComplete);
        correlator.Clear();
        Assert.True(correlator.Observe(Observation("cleared", first, now.AddSeconds(3)), now.AddSeconds(3)).AttributionComplete);
    }

    [Fact]
    /// <summary>RT priority ages admission without masking explicit caller cancellation or adding workers.</summary>
    public async Task ContinuousRealtimeActivity_DoesNotStarveBulkAdmission()
    {
        using var held = RealtimeScanPriority.Enter();
        var watch = Stopwatch.StartNew();
        await RealtimeScanPriority.WaitAsync(default).WaitAsync(TimeSpan.FromSeconds(3));
        Assert.InRange(watch.ElapsedMilliseconds, 150, 2999);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => RealtimeScanPriority.WaitAsync(cancelled.Token));
    }

    [Fact]
    /// <summary>A slow storage classifier cannot prevent another writer or completion from acquiring the queue lock.</summary>
    public async Task StorageCallback_DoesNotHoldQueueLock()
    {
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var queue = new VolumeScanQueue<int>(8, _ => "fixture-volume", _ =>
        { entered.TrySetResult(); if (!release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException(); return 1; });
        await queue.WriteAsync(1, default);
        var read = Task.Run(() => queue.ReadAsync(default));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            await queue.WriteAsync(2, default).WaitAsync(TimeSpan.FromSeconds(1));
            await Task.Run(() => queue.Complete()).WaitAsync(TimeSpan.FromSeconds(1));
        }
        finally { release.Set(); }
        using var lease = await read.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(1, lease!.Item);
    }

    [Theory]
    [InlineData("normal")]
    [InlineData("no-lease")]
    [InlineData("expired-during-acquire")]
    [InlineData("executor-fault")]
    /// <summary>Missing, expired and faulting leases fail safely; the executor receives the same target before disposal.</summary>
    public async Task Broker_RequiresSameRetainedTargetAndAlwaysDisposes(string mode)
    {
        var time = new FixedTime();
        var file = new ProtectionFileIdentity("test-volume", "test-file", new string('A', 64));
        var caller = new ProtectionCaller("S-1-5-21-100", false);
        var snapshot = new ProtectionEvidenceSnapshot(file, null, [], true, time.GetUtcNow());
        var adapter = new LeaseAdapter(file, mode, time);
        var broker = new ProtectionActionBroker(adapter, adapter, time);
        var permit = Assert.IsType<ActionPermit>(await broker.ProposeAsync(snapshot, ProtectionActionKind.Quarantine, caller, false));
        var receipt = await broker.ExecuteAsync(permit, caller);
        Assert.Equal(mode == "normal" || mode == "executor-fault" ? 1 : 0, adapter.Executions);
        Assert.Equal(mode != "no-lease", adapter.Target.Disposed);
        Assert.Equal(mode switch { "normal" => ProtectionActionOutcome.Failed, "executor-fault" => ProtectionActionOutcome.Unknown,
            _ => ProtectionActionOutcome.Rejected }, receipt.Outcome);
        Assert.Equal(ProtectionActionOutcome.Rejected, (await broker.ExecuteAsync(permit, caller)).Outcome);
    }

    private static BehaviorObservation Observation(string id, BehaviorProcessIdentity actor, DateTimeOffset time) =>
        new(id, "write", BehaviorObservationKind.FileWritten, actor, time, "Benign synthetic observation",
            BehaviorAttribution.EtwThreadGeneration, 10);
    private static RealTimeVerdictProcessor Processor(ReviewStageOneFixture fixture, IDetectionHub hub) =>
        new(fixture.HashService, fixture.SignatureVerifier, new ZeroRisk(), null, null, null, detectionHub: hub);
    private sealed class FixedHub(DetectionResult result) : IDetectionHub
    {
        internal int Calls;
        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => [];
        public void RegisterDetector(IDetectorPlugin detector) => throw new NotSupportedException();
        public bool UnregisterDetector(string id) => false;
        public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken token = default)
        { Calls++; return Task.FromResult(result); }
    }
    private sealed class EmptyDetector : IDetectorPlugin
    {
        public string DetectorId => "inert-empty";
        public string DisplayName => "Synthetic no-evidence detector";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticApi;
        public int Priority => 1;
        public bool IsEnabled { get; set; } = true;
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
            => Task.FromResult<IEnumerable<SecurityEvidence>>([]);
    }
    private sealed class ZeroRisk : IRiskScoringEngine
    {
        public Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(FileAnalysisResult result,
            CancellationToken token = default) => Task.FromResult((0, RiskLevel.Clean, new List<string>()));
    }
    private sealed class BlockedHash(OperatingSystemFileBlockKind kind) : IHashService
    {
        public Task<string> ComputeSha256Async(string path, CancellationToken token = default)
            => Task.FromException<string>(new OperatingSystemFileBlockException(kind));
        public Task<string> ComputeSha1Async(string path, CancellationToken token = default) => throw new NotSupportedException();
    }
    private sealed class CodedIo : IOException
    { internal CodedIo(int code) : base("virus malware EICAR text alone must not authorize anything") { HResult = code; } }
    private sealed class FixedTime : TimeProvider
    {
        internal DateTimeOffset Now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class Target(ProtectionActionValidation proof) : IValidatedProtectionTarget
    {
        internal bool Disposed;
        public ProtectionActionValidation Validation => proof;
        public ValueTask DisposeAsync() { Disposed = true; return ValueTask.CompletedTask; }
    }
    private sealed class LeaseAdapter(ProtectionFileIdentity file, string mode, FixedTime time) : IProtectionActionValidator, IProtectionActionExecutor
    {
        private readonly ProtectionActionValidation _proof = new(true, true, false, false, "fixture-revision", file, null, "Fixture");
        internal readonly Target Target = new(new(true, true, false, false, "fixture-revision", file, null, "Fixture"));
        internal int Executions;
        public Task<ProtectionActionValidation> ValidateAsync(ProtectionEvidenceSnapshot snapshot, ProtectionActionKind kind,
            ProtectionCaller caller, CancellationToken token) => Task.FromResult(_proof);
        public Task<IValidatedProtectionTarget?> AcquireAsync(ProtectionEvidenceSnapshot snapshot, ProtectionActionKind kind,
            ProtectionCaller caller, CancellationToken token)
        {
            if (mode == "expired-during-acquire") time.Now += TimeSpan.FromSeconds(16);
            return Task.FromResult<IValidatedProtectionTarget?>(mode == "no-lease" ? null : Target);
        }
        public Task<ActionReceipt> ExecuteAsync(ActionPermit permit, IValidatedProtectionTarget target, CancellationToken token)
        {
            Assert.Same(Target, target); Assert.False(Target.Disposed); Executions++;
            if (mode == "executor-fault") throw new IOException("Synthetic inert failure");
            return Task.FromResult(new ActionReceipt(Guid.NewGuid(), permit.Id, permit.Kind, ProtectionActionOutcome.Failed,
                "InertActionOnly", time.GetUtcNow()));
        }
    }
    private sealed class FailingAudit : IAuditLogService
    {
        public Task LogActionAsync(AuditAction action, string targetType, string targetName, string? targetPath = null,
            string? details = null, AuditResult result = AuditResult.Success, string? errorMessage = null, CancellationToken cancellationToken = default)
            => Task.FromException(new IOException("Synthetic audit storage failure"));
        public Task<List<AuditLogEntry>> GetLogsAsync(DateTime? from = null, DateTime? to = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new List<AuditLogEntry>());
        public Task ClearLogsAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
    private sealed class InertVault(Action beforeAction) : IQuarantineService, IContentBoundQuarantineService
    {
        internal int Calls;
        public string? LastError => null;
        public event Action<QuarantineEntry>? OnFileQuarantined { add { } remove { } }
        public event Action<int>? OnFileRestored { add { } remove { } }
        public event Action<int>? OnFileDeleted { add { } remove { } }
        public Task<bool> TryQuarantineFileAsync(string path, string reason, string hash, CancellationToken token = default)
        { beforeAction(); Calls++; return Task.FromResult(true); }
        public Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken token = default) => throw new NotSupportedException();
        public Task<bool> RestoreFileAsync(int id, CancellationToken token = default) => throw new NotSupportedException();
        public Task<bool> RestoreFileAsync(int id, string? destination, CancellationToken token = default) => throw new NotSupportedException();
        public Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken token = default) => Task.FromResult(new List<QuarantineEntry>());
        public Task<bool> DeleteQuarantinedAsync(int id, CancellationToken token = default) => throw new NotSupportedException();
        public Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken token = default) => Task.FromResult<QuarantineEntry?>(null);
    }
}
