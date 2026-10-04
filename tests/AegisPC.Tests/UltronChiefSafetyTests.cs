using AegisPC.Contracts.Protection;
using AegisPC.Security.UltronAI;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Pure local policy/adversarial permit fixtures; no live process, service or vault is touched.</summary>
public sealed class UltronChiefSafetyTests
{
    private static readonly ProtectionFileIdentity FileIdentity = new("volume-test", "file-test", new string('A', 64));
    private static readonly ProtectionCaller Caller = new("S-1-5-21-100", false);
    private static ProtectionEvidenceSnapshot Snapshot(DateTimeOffset now) => new(FileIdentity, null,
        new[] { new ProtectionEvidence("event", "hash", ProtectionEvidenceFamily.ConfirmedContent, 100, now, "Test claim", true) }, true, now);

    /// <summary>Repeated detectors observing one feature cannot create independent confirmation or process-kill authority.</summary>
    [Fact]
    public void DuplicateFeaturesAndFamilyCaps_DoNotAuthorizeAction()
    {
        var now = DateTimeOffset.UtcNow;
        var evidence = Enumerable.Range(0, 100).Select(_ => new ProtectionEvidence("one-event", "same-feature",
            ProtectionEvidenceFamily.Process, 100, now, "Encoded script observation")).ToArray();
        var decision = new UltronDecisionEngine().Evaluate(Snapshot(now) with { Evidence = evidence });
        Assert.Equal(25, decision.ReviewPriority);
        Assert.Equal(ProtectionActionKind.RequestReview, decision.Recommendation);
    }
    /// <summary>Even an asserted exact malware label cannot bypass the default native pilot gate.</summary>
    [Fact]
    public async Task FakeConfirmedContent_DefaultAdapterCannotIssuePermit()
    {
        var adapter = new PilotGatedActionAdapter();
        var broker = new ProtectionActionBroker(adapter, adapter);
        Assert.Null(await broker.ProposeAsync(Snapshot(DateTimeOffset.UtcNow), ProtectionActionKind.Quarantine, Caller, true));
    }
    /// <summary>Expiry, SID mismatch, forged fields, replay and changed proof are rejected without native actions.</summary>
    [Theory]
    [InlineData("expired")]
    [InlineData("other-user")]
    [InlineData("forged-kind")]
    [InlineData("changed-hash")]
    [InlineData("changed-revision")]
    [InlineData("critical")]
    public async Task UnsafePermit_IsRejected(string condition)
    {
        var time = new FixtureTime();
        var adapter = new FixtureAdapter();
        var broker = new ProtectionActionBroker(adapter, adapter, time);
        var permit = Assert.IsType<ActionPermit>(await broker.ProposeAsync(Snapshot(time.GetUtcNow()), ProtectionActionKind.Quarantine, Caller, false));
        var caller = Caller;
        if (condition == "expired") time.Advance(TimeSpan.FromSeconds(16));
        if (condition == "other-user") caller = new("S-1-5-21-200", true);
        if (condition == "forged-kind") permit = permit with { Kind = ProtectionActionKind.TerminateVerifiedActor };
        if (condition == "changed-hash") adapter.Proof = adapter.Proof with { File = FileIdentity with { SHA256 = new string('B', 64) } };
        if (condition == "changed-revision") adapter.Proof = adapter.Proof with { EvidenceRevision = "changed" };
        if (condition == "critical") adapter.Proof = adapter.Proof with { CriticalObject = true };
        Assert.Equal(ProtectionActionOutcome.Rejected, (await broker.ExecuteAsync(permit, caller)).Outcome);
        Assert.Equal(0, adapter.Executions);
    }
    /// <summary>Concurrent consumption produces one real receipt; failed quarantine never grants termination permission.</summary>
    [Fact]
    public async Task SingleUsePermit_FailedActionDoesNotEscalate()
    {
        var time = new FixtureTime();
        var adapter = new FixtureAdapter();
        var broker = new ProtectionActionBroker(adapter, adapter, time);
        var permit = Assert.IsType<ActionPermit>(await broker.ProposeAsync(Snapshot(time.GetUtcNow()), ProtectionActionKind.Quarantine, Caller, false));
        var receipts = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => broker.ExecuteAsync(permit, Caller)));
        Assert.Single(receipts.Where(r => r.Outcome == ProtectionActionOutcome.Failed));
        Assert.Equal(1, adapter.Executions);
        Assert.Null(await broker.ProposeAsync(Snapshot(time.GetUtcNow()), ProtectionActionKind.TerminateVerifiedActor, Caller, true));
    }
    /// <summary>PID reuse or boot change is a target change even when the same executable hash remains.</summary>
    [Fact]
    public async Task ProcessCreationIdentityChange_IsRejected()
    {
        var time = new FixtureTime();
        var process = new ProtectionProcessIdentity(123456, time.GetUtcNow().AddMinutes(-1), "test-boot", FileIdentity);
        var snapshot = Snapshot(time.GetUtcNow()) with { Process = process };
        var adapter = new FixtureAdapter();
        adapter.Proof = adapter.Proof with { Process = process };
        var broker = new ProtectionActionBroker(adapter, adapter, time);
        var permit = Assert.IsType<ActionPermit>(await broker.ProposeAsync(snapshot, ProtectionActionKind.Quarantine, Caller, false));
        adapter.Proof = adapter.Proof with { Process = process with { StartedAtUtc = time.GetUtcNow() } };
        Assert.Equal(ProtectionActionOutcome.Rejected, (await broker.ExecuteAsync(permit, Caller)).Outcome);
    }
    /// <summary>The 24-hour preference is hash/family/user scoped and cannot suppress authoritative evidence.</summary>
    [Fact]
    public void BehavioralTrust_ExpiresAndCannotHideConfirmedContent()
    {
        var time = new FixtureTime();
        var trust = new BehaviorNotificationTrustStore(time);
        Assert.True(trust.TrustFor24Hours(Caller.OwnerSid, FileIdentity.SHA256, "Packing"));
        Assert.True(trust.ReduceSimilarNotification(Caller.OwnerSid, FileIdentity.SHA256.ToLowerInvariant(), "Packing", false));
        Assert.False(trust.ReduceSimilarNotification(Caller.OwnerSid, FileIdentity.SHA256, "Packing", true));
        Assert.False(trust.ReduceSimilarNotification("S-1-5-21-200", FileIdentity.SHA256, "Packing", false));
        Assert.False(trust.ReduceSimilarNotification(Caller.OwnerSid, new string('B', 64), "Packing", false));
        time.Advance(TimeSpan.FromHours(24));
        Assert.False(trust.ReduceSimilarNotification(Caller.OwnerSid, FileIdentity.SHA256, "Packing", false));
    }
    /// <summary>Unknown resource samples remain absent and a stable baseline never implies statistically certain malware.</summary>
    [Fact]
    public void RobustStatistics_MissingAndNonfiniteSamplesAreExplicit()
    {
        var statistics = new BehaviorReviewStatistics();
        Assert.Null(statistics.Snapshot().Median);
        Assert.False(statistics.Add(double.NaN));
        Assert.False(statistics.Add(double.PositiveInfinity));
        for (int i = 0; i < 200; i++) Assert.True(statistics.Add(10));
        Assert.Equal(128, statistics.Snapshot().Count);
        Assert.Equal(10, statistics.Snapshot().Median);
        Assert.Equal(0, statistics.Snapshot().Mad);
    }
    /// <summary>Health misses are sampled by elapsed time, not caller polling rate; recovery is bounded and maintenance suppresses it.</summary>
    [Fact]
    public void GuardianHealth_BoundedRecoveryAndMaintenance()
    {
        var time = new FixtureTime();
        var health = new GuardianHealthMonitor(time);
        Assert.Equal(GuardianHealthState.Unverified, health.Capture().State);
        health.ObserveHeartbeat(0, false);
        Assert.Equal(GuardianHealthState.Degraded, health.Capture().State);
        health.ObserveHeartbeat(2, true);
        Assert.Equal(GuardianHealthState.Healthy, health.Capture().State);
        time.Advance(TimeSpan.FromSeconds(15));
        Assert.Equal(3, health.Capture().ConsecutiveMissingHeartbeats);
        Assert.False(health.TryReserveRestart());
        time.Advance(TimeSpan.FromSeconds(5)); Assert.True(health.TryReserveRestart());
        Assert.False(health.TryReserveRestart());
        time.Advance(TimeSpan.FromSeconds(15)); Assert.True(health.TryReserveRestart());
        time.Advance(TimeSpan.FromSeconds(60)); Assert.True(health.TryReserveRestart());
        time.Advance(TimeSpan.FromSeconds(60)); Assert.False(health.TryReserveRestart());
        health.SetMaintenance(TimeSpan.FromMinutes(5));
        Assert.Equal(GuardianHealthState.Maintenance, health.Capture().State);
        Assert.False(health.TryReserveRestart());
    }
    private sealed class FixtureTime : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        internal void Advance(TimeSpan duration) => _now += duration;
    }
    private sealed class FixtureAdapter : IProtectionActionValidator, IProtectionActionExecutor
    {
        internal ProtectionActionValidation Proof = new(true, true, false, false, "verified-test-only", FileIdentity, null, "Fixture");
        internal int Executions;
        public Task<ProtectionActionValidation> ValidateAsync(ProtectionEvidenceSnapshot snapshot, ProtectionActionKind kind, ProtectionCaller caller, CancellationToken token) => Task.FromResult(Proof);
        public Task<ActionReceipt> ExecuteAsync(ActionPermit permit, CancellationToken token)
        { Interlocked.Increment(ref Executions); return Task.FromResult(new ActionReceipt(Guid.NewGuid(), permit.Id, permit.Kind, ProtectionActionOutcome.Failed, "SyntheticQuarantineFailure", DateTimeOffset.UtcNow)); }
    }
}
