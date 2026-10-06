using AegisPC.Contracts.Protection;
using AegisPC.Security.UltronAI;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Inert target discrimination and unopened native pilot tests; no real security action is attempted.</summary>
public sealed class ProtectionTargetReviewTests
{
    [Fact]
    public void NetworkAndRemotePermitsDoNotInventFileOrProcessIdentity()
    {
        var network = Permit(new ProtectionNetworkTarget("owned-scope", DateTimeOffset.UtcNow.AddMinutes(15)));
        var remote = Permit(new ProtectionRemoteTarget("2001:db8::1", 3389, "TCP", 1, "S-1-5-21-100"));
        Assert.Null(network.File);
        Assert.Null(network.Process);
        Assert.Null(remote.File);
        Assert.Null(remote.Process);
    }

    [Fact]
    public async Task UnsupportedNativeTargetCannotObtainPermitEvenWhenUiClaimsConfirmation()
    {
        var adapter = new PilotGatedActionAdapter();
        var broker = new ProtectionActionBroker(adapter, adapter);
        var request = new ProtectionActionRequest(new ProtectionNetworkTarget("scope", DateTimeOffset.UtcNow.AddMinutes(15)),
            [new("ui-event", "fake-confirmed", ProtectionEvidenceFamily.ConfirmedContent, 100, DateTimeOffset.UtcNow, "Untrusted UI claim", true)],
            true, DateTimeOffset.UtcNow);
        Assert.Null(await broker.ProposeTargetAsync(request, ProtectionActionKind.IsolateNetwork, new("S-1-5-21-100", true), true));
        Assert.Equal(ProtectionActionOutcome.Rejected,
            (await broker.ExecuteAsync(Permit(request.Target), new("S-1-5-21-100", true))).Outcome);
    }

    [Fact]
    public void LegacyFileConstructorCarriesTheSameImmutableTargetIdentity()
    {
        var file = new ProtectionFileIdentity("volume", "file", new string('A', 64));
        var process = new ProtectionProcessIdentity(1, DateTimeOffset.UtcNow.AddMinutes(-1), "boot", file);
        var permit = new ActionPermit(Guid.NewGuid(), "S-1-5-21-100", ProtectionActionKind.Quarantine,
            file, process, "revision", "policy", DateTimeOffset.UtcNow.AddSeconds(15));
        Assert.Equal(file, permit.File);
        Assert.Equal(process, permit.Process);
        Assert.Equal(new ProtectionFileTarget(file, process), permit.Target);
    }

    private static ActionPermit Permit(ProtectionActionTarget target) => new(Guid.NewGuid(), "S-1-5-21-100",
        ProtectionActionKind.IsolateNetwork, target, "unverified", "pilot", DateTimeOffset.UtcNow.AddSeconds(15));
}
