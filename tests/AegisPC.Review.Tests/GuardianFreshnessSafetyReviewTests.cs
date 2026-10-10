using System;
using AegisPC.Security.UltronAI;
using AegisPC.Contracts.Protection;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Pure clock/health tests; no core IPC, native recovery or vault access is performed.</summary>
public sealed class GuardianFreshnessSafetyReviewTests
{
    /// <summary>Stale component counts and vault assertions expire with the core health lease.</summary>
    [Fact]
    public void MissingHeartbeat_WithdrawsStaleComponentClaims()
    {
        var clock = new Clock(); var health = new GuardianHealthMonitor(clock);
        health.ObserveHeartbeat(3, true);
        Assert.Equal(GuardianHealthState.Healthy, health.Capture().State);
        clock.Now += TimeSpan.FromSeconds(15);
        var expired = health.Capture();
        Assert.Equal(GuardianHealthState.MissingHeartbeat, expired.State);
        Assert.Equal(0, expired.ActiveObservers);
        Assert.False(expired.VaultOwnershipVerified);
        Assert.Contains("CoreHealthLeaseUnavailableOrExpired", expired.Limitations);
    }

    /// <summary>A backwards clock cannot turn future health into current protection or recovery authority.</summary>
    [Fact]
    public void FutureHeartbeat_IsUnverifiedAndCannotReserveRecovery()
    {
        var clock = new Clock(); var health = new GuardianHealthMonitor(clock);
        health.ObserveHeartbeat(2, true); clock.Now -= TimeSpan.FromMinutes(1);
        Assert.Equal(GuardianHealthState.Unverified, health.Capture().State);
        Assert.False(health.Capture().VaultOwnershipVerified);
        Assert.False(health.TryReserveRestart());
    }

    /// <summary>A source-pilot self heartbeat cannot claim actual observers or independent vault ownership.</summary>
    [Fact]
    public void PilotHeartbeat_StillHasExplicitGaps()
    {
        var health = new GuardianHealthMonitor(new Clock()); health.ObserveHeartbeat(0, false);
        Assert.Equal(GuardianHealthState.Degraded, health.Capture().State);
        Assert.Contains("ExclusiveVaultOwnershipNotVerified", health.Capture().Limitations);
        Assert.False(health.TryReserveRestart());
    }

    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
