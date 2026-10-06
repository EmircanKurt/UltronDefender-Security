using System.Xml;
using AegisPC.Contracts.Protection;
using AegisPC.Service.Remote;
using AegisPC.Service.Wireless;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Pure policy/fake-adapter fixtures; no Windows log subscription, native session/radio capture or network mutation.</summary>
public sealed class RemoteWirelessReviewTests
{
    private static readonly DateTime Now = new(2026, 10, 5, 12, 0, 0, DateTimeKind.Utc);
    private static readonly Guid WifiId = new("735ba67a-1725-4cdb-aa78-d3203ce393a0");

    [Theory]
    [InlineData(299, LocalConsolePresence.Present, false)]
    [InlineData(300, LocalConsolePresence.Away, true)]
    [InlineData(600, LocalConsolePresence.Away, true)]
    public void ConsoleIdle_UsesFiveMinuteBoundaryWithoutEnforcement(int seconds, LocalConsolePresence expected, bool wouldDeny)
    {
        var result = Evaluate(Console() with { IdleDuration = TimeSpan.FromSeconds(seconds) });
        Assert.Equal(expected, result.ConsolePresence);
        Assert.Equal(wouldDeny, result.WouldDenyNewRdpWhileAway);
        Assert.False(result.NativeEnforcementActive);
    }

    [Fact]
    public void RemoteInput_CannotCreatePhysicalPresenceOrClearAfk()
    {
        var result = Evaluate(Console() with { ClientProtocolType = 2, IdleDuration = TimeSpan.Zero });
        Assert.Equal(LocalConsolePresence.Unknown, result.ConsolePresence);
        Assert.False(result.WouldDenyNewRdpWhileAway);
    }

    [Fact]
    public void LockedConsole_DoesNotRequireFabricatedIdleReading()
    {
        var result = Evaluate(Console() with { IsLocked = true, IdleDuration = null });
        Assert.Equal(LocalConsolePresence.Locked, result.ConsolePresence);
        Assert.True(result.WouldDenyNewRdpWhileAway);
    }

    [Fact]
    public void NoConsole_IsExplicitlyDifferentFromQueryFailure()
    {
        Assert.Equal(LocalConsolePresence.NoLocalSession, Evaluate(Console() with { SessionId = null }).ConsolePresence);
        Assert.Equal(LocalConsolePresence.Unknown,
            Evaluate(Console() with { Availability = SecurityObservationAvailability.Unavailable, SessionId = null }).ConsolePresence);
    }

    [Theory]
    [InlineData(-16)]
    [InlineData(1)]
    public void StaleOrFutureConsole_IsUnknown(int offsetSeconds)
    {
        Assert.Equal(LocalConsolePresence.Unknown, Evaluate(Console() with { CapturedAtUtc = Now.AddSeconds(offsetSeconds) }).ConsolePresence);
    }

    [Fact]
    public void UnknownLockOrIdle_IsNotPresentOrAfk()
    {
        Assert.Equal(LocalConsolePresence.Unknown, Evaluate(Console() with { IsLocked = null }).ConsolePresence);
        Assert.Equal(LocalConsolePresence.Unknown, Evaluate(Console() with { IdleDuration = null }).ConsolePresence);
        Assert.Equal(LocalConsolePresence.Unknown, Evaluate(Console() with { IdleDuration = TimeSpan.FromSeconds(-1) }).ConsolePresence);
    }

    [Fact]
    public void NonUtcClockAndObservation_AreNotFresh()
    {
        Assert.Equal(LocalConsolePresence.Unknown, Evaluate(Console() with { CapturedAtUtc = DateTime.SpecifyKind(Now, DateTimeKind.Unspecified) }).ConsolePresence);
        var policy = new RemoteProtectionPolicy();
        var result = policy.Evaluate(DateTime.SpecifyKind(Now, DateTimeKind.Local), Console(), Batch());
        Assert.Equal(LocalConsolePresence.Unknown, result.ConsolePresence);
        Assert.False(result.NativeEnforcementActive);
    }

    [Fact]
    public void FiveFailures_ProposeTenMinuteLeaseNotAppliedBlock()
    {
        var result = new RemoteProtectionPolicy().Evaluate(Now, Console(), Batch(Failures(5)));
        var proposal = Assert.Single(result.RepeatedFailureProposals);
        Assert.Equal(5, proposal.DistinctFailures);
        Assert.Equal(Now.AddMinutes(10), proposal.SuggestedUntilUtc);
        Assert.False(proposal.Applied);
        Assert.False(result.NativeEnforcementActive);
    }

    [Fact]
    public void DuplicateFailures_DoNotReachThreshold()
    {
        var same = Failures(1).Single();
        var result = new RemoteProtectionPolicy().Evaluate(Now, Console(), Batch(Enumerable.Repeat(same, 10).ToArray()));
        Assert.Empty(result.RepeatedFailureProposals);
    }

    [Fact]
    public void UncorrelatedNlaNetworkFailures_AreNotRdpDenialProposals()
    {
        var records = Failures(5).Select(record => record with { IsRdpCorrelated = false }).ToArray();
        Assert.Empty(new RemoteProtectionPolicy().Evaluate(Now, Console(), Batch(records)).RepeatedFailureProposals);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("not-an-address")]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    public void MissingLoopbackOrInvalidSource_IsNotDenied(string address)
    {
        var records = Failures(5).Select(record => record with { RemoteAddress = address }).ToArray();
        Assert.Empty(new RemoteProtectionPolicy().Evaluate(Now, Console(), Batch(records)).RepeatedFailureProposals);
    }

    [Fact]
    public void MappedIpv4_NormalizesToOneTarget()
    {
        var records = Failures(5).Select((record, index) => record with
            { RemoteAddress = index % 2 == 0 ? "192.0.2.10" : "::ffff:192.0.2.10" }).ToArray();
        Assert.Equal("192.0.2.10", Assert.Single(new RemoteProtectionPolicy().Evaluate(Now, Console(), Batch(records))
            .RepeatedFailureProposals).RemoteAddress);
    }

    [Fact]
    public void InvalidFutureSuccessAndOldEvents_DoNotEscalate()
    {
        var policy = new RemoteProtectionPolicy();
        foreach (var invalid in new[]
        {
            Failures(5).Select(x => x with { TimestampUtc = Now.AddSeconds(1) }).ToArray(),
            Failures(5).Select(x => x with { TimestampUtc = Now.AddSeconds(-121) }).ToArray(),
            Failures(5).Select(x => x with { TimestampUtc = DateTime.SpecifyKind(Now, DateTimeKind.Unspecified) }).ToArray(),
            Failures(5).Select(x => x with { IsAuthenticationFailure = false }).ToArray()
        }) Assert.Empty(policy.Evaluate(Now, Console(), Batch(invalid)).RepeatedFailureProposals);
    }

    [Fact]
    public void LeaseExpires_AndBackwardsClockDoesNotPreserveStaleAdvice()
    {
        var policy = new RemoteProtectionPolicy();
        Assert.Single(policy.Evaluate(Now, Console(), Batch(Failures(5))).RepeatedFailureProposals);
        var later = Now.AddMinutes(10);
        Assert.Empty(policy.Evaluate(later, Console() with { CapturedAtUtc = later }, Batch() with { CapturedAtUtc = later }).RepeatedFailureProposals);
        Assert.Single(policy.Evaluate(Now, Console(), Batch(Failures(5))).RepeatedFailureProposals);
        var earlier = Now.AddSeconds(-1);
        Assert.Empty(policy.Evaluate(earlier, Console() with { CapturedAtUtc = earlier }, Batch() with { CapturedAtUtc = earlier }).RepeatedFailureProposals);
    }

    [Fact]
    public void BoundedBatch_ReportsIncompleteReviewAndPreservesLostCount()
    {
        var result = new RemoteProtectionPolicy().Evaluate(Now, Console(), Batch(Failures(300)) with { LostEvents = 7 });
        Assert.Equal(7, result.LostEvents);
        Assert.Contains(result.Limitations, text => text.Contains("per-refresh", StringComparison.Ordinal));
        Assert.False(result.NativeEnforcementActive);
    }

    [Fact]
    public void SecurityXml_IsProviderBoundAndDtdFree()
    {
        var parsed = WindowsRdpLogonObservationSource.ParseSecurityEventXml(EventXml(10));
        Assert.NotNull(parsed);
        Assert.True(parsed!.IsRdpCorrelated);
        Assert.True(parsed.IsAuthenticationFailure);
        Assert.Equal(Now, parsed.TimestampUtc);
        Assert.Null(WindowsRdpLogonObservationSource.ParseSecurityEventXml(EventXml(10).Replace("Microsoft-Windows-Security-Auditing", "Other-Provider")));
        Assert.Throws<XmlException>(() => WindowsRdpLogonObservationSource.ParseSecurityEventXml("<!DOCTYPE Event [<!ENTITY x 'payload'>]><Event>&x;</Event>"));
    }

    [Fact]
    public void SecurityXml_Type3RemainsUncorrelatedAndNoUsernameIsReturned()
    {
        var parsed = WindowsRdpLogonObservationSource.ParseSecurityEventXml(EventXml(3));
        Assert.NotNull(parsed);
        Assert.False(parsed!.IsRdpCorrelated);
        Assert.Equal(string.Empty, parsed.TargetSid);
        Assert.DoesNotContain("private-user", parsed.EventIdentity);
    }

    [Fact]
    public void InertNativeSource_IsPendingWithoutStartingSubscription()
    {
        using var source = new WindowsRdpLogonObservationSource();
        var batch = source.Drain(Now);
        Assert.Equal(SecurityObservationAvailability.Pending, batch.Availability);
        Assert.Empty(batch.Events);
        // Constructors are inert: no Capture/Start methods are called on any real native adapter.
        Assert.NotNull(new WindowsConsolePresenceObserver());
        Assert.NotNull(new WindowsWirelessInventoryObserver());
    }

    [Theory]
    [InlineData(false, 1u, 0u, ObservedWifiSecurity.Open)]
    [InlineData(true, 7u, 2u, ObservedWifiSecurity.Legacy)]
    [InlineData(true, 7u, 4u, ObservedWifiSecurity.Wpa2)]
    [InlineData(true, 9u, 4u, ObservedWifiSecurity.Wpa3)]
    [InlineData(true, 8u, 9u, ObservedWifiSecurity.Wpa3)]
    [InlineData(true, 11u, 8u, ObservedWifiSecurity.Wpa3)]
    [InlineData(true, 10u, 4u, ObservedWifiSecurity.Unknown)]
    [InlineData(true, 0x80000001u, 4u, ObservedWifiSecurity.Unknown)]
    [InlineData(true, 7u, 0x80000001u, ObservedWifiSecurity.Unknown)]
    public void WifiAlgorithms_UnknownAndOweDoNotBecomeAuthenticatedWpa(bool enabled, uint authentication, uint cipher, ObservedWifiSecurity expected)
    {
        Assert.Equal(expected, WirelessProtectionPolicy.ClassifyWifiSecurity(enabled, authentication, cipher));
    }

    [Fact]
    public void WifiDowngradeAndRoaming_AreReviewSignalsNotAttackVerdicts()
    {
        var policy = new WirelessProtectionPolicy();
        var previous = Wifi(ObservedWifiSecurity.Wpa3, "AABBCCDDEEFF");
        Assert.Empty(policy.Evaluate(Now, Wireless([previous])).ReviewSignals);
        var next = previous with { Security = ObservedWifiSecurity.Wpa2, Bssid = "AABBCCDD0011" };
        var result = policy.Evaluate(Now, Wireless([next]));
        Assert.Contains(result.ReviewSignals, signal => signal.RuleId == "WifiSecurityChanged");
        Assert.Contains(result.ReviewSignals, signal => signal.RuleId == "ReportedAccessPointChanged" && signal.Explanation.Contains("not proof"));
        Assert.False(result.NativeEnforcementActive);
    }

    [Fact]
    public void OpenWifi_PersistsAsConfigurationWarningNotAutomaticDisconnect()
    {
        var policy = new WirelessProtectionPolicy();
        var inventory = Wireless([Wifi(ObservedWifiSecurity.Open, "AA")]);
        Assert.Single(policy.Evaluate(Now, inventory).ReviewSignals);
        Assert.Single(policy.Evaluate(Now, inventory).ReviewSignals);
        Assert.False(policy.Evaluate(Now, inventory).NativeEnforcementActive);
    }

    [Fact]
    public void UnavailableOrStaleWireless_DoesNotClaimWorkingSecurity()
    {
        var policy = new WirelessProtectionPolicy();
        var unavailable = Wireless([Wifi(ObservedWifiSecurity.Open, "AA")]) with { WifiAvailability = SecurityObservationAvailability.Unavailable };
        Assert.Empty(policy.Evaluate(Now, unavailable).ReviewSignals);
        var future = policy.Evaluate(Now, Wireless([Wifi(ObservedWifiSecurity.Wpa3, "AA")]) with { CapturedAtUtc = Now.AddSeconds(1) });
        Assert.Equal(SecurityObservationAvailability.Unavailable, future.Inventory.WifiAvailability);
        Assert.Empty(future.Inventory.WifiConnections);
    }

    [Fact]
    public void NewBluetooth_IsReviewOnlyAndExistingDevicesDoNotAlarmOnBaseline()
    {
        var policy = new WirelessProtectionPolicy();
        var first = new BluetoothDeviceObservation { Address = "001122334455", Remembered = true };
        Assert.Empty(policy.Evaluate(Now, Wireless([]) with { BluetoothDevices = [first] }).ReviewSignals);
        var second = first with { Address = "AABBCCDDEEFF" };
        var next = policy.Evaluate(Now, Wireless([]) with { BluetoothDevices = [first, second] });
        Assert.Equal("NewRememberedBluetoothDevice", Assert.Single(next.ReviewSignals).RuleId);
        Assert.False(next.NativeEnforcementActive);
        Assert.Empty(policy.Evaluate(Now, Wireless([]) with { BluetoothDevices = [first, second] }).ReviewSignals);
    }

    [Fact]
    public void WirelessInventory_IsBounded()
    {
        var connections = Enumerable.Range(0, 100).Select(_ => Wifi(ObservedWifiSecurity.Open, null) with { InterfaceId = Guid.NewGuid() }).ToArray();
        var result = new WirelessProtectionPolicy().Evaluate(Now, Wireless(connections));
        Assert.Equal(32, result.Inventory.WifiConnections.Count);
        Assert.Contains(result.Inventory.Limitations, text => text.Contains("budget"));
        Assert.True(result.ReviewSignals.Count <= 64);
    }

    [Fact]
    public void ServiceMonitors_UseInjectedFakesAndCacheTruthfulSnapshot()
    {
        var remote = new RemoteProtectionMonitor(new FakeConsole(), new FakeLogons(), new());
        Assert.Equal(SecurityObservationAvailability.Pending, remote.CurrentSnapshot.ConsoleAvailability);
        Assert.Equal(LocalConsolePresence.Present, remote.Refresh(Now).ConsolePresence);
        var wireless = new WirelessProtectionMonitor(new FakeWireless(), new());
        Assert.Equal(SecurityObservationAvailability.Pending, wireless.CurrentSnapshot.Inventory.WifiAvailability);
        Assert.Equal(SecurityObservationAvailability.Unavailable, wireless.Refresh(Now).Inventory.WifiAvailability);
        Assert.False(remote.CurrentSnapshot.NativeEnforcementActive);
        Assert.False(wireless.CurrentSnapshot.NativeEnforcementActive);
    }

    private static ConsolePresenceObservation Console() => new()
    { CapturedAtUtc = Now, SessionId = 1, ClientProtocolType = 0, IsLocked = false, IdleDuration = TimeSpan.Zero,
        Availability = SecurityObservationAvailability.Available };
    private static RdpLogonBatch Batch(params RdpLogonObservation[] events) => new()
    { CapturedAtUtc = Now, Availability = SecurityObservationAvailability.Partial, Events = events };
    private static RemoteProtectionSnapshot Evaluate(ConsolePresenceObservation console) => new RemoteProtectionPolicy().Evaluate(Now, console, Batch());
    private static RdpLogonObservation[] Failures(int count) => Enumerable.Range(0, count).Select(index => new RdpLogonObservation
    { EventIdentity = $"fixture-{index}", TimestampUtc = Now.AddSeconds(-index % 60), RemoteAddress = "192.0.2.10",
        TargetSid = "S-1-5-21-100-100-100-1001", IsAuthenticationFailure = true, IsRdpCorrelated = true }).ToArray();
    private static WifiConnectionObservation Wifi(ObservedWifiSecurity security, string? bssid) => new()
    { InterfaceId = WifiId, Ssid = "fixture-network", Security = security, Bssid = bssid };
    private static WirelessInventorySnapshot Wireless(IReadOnlyList<WifiConnectionObservation> connections) => new()
    { CapturedAtUtc = Now, WifiAvailability = SecurityObservationAvailability.Available,
        BluetoothAvailability = SecurityObservationAvailability.Available, WifiConnections = connections };
    private static string EventXml(int type) => $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>
          <TimeCreated SystemTime="2026-10-05T12:00:00.0000000Z"/><EventRecordID>42</EventRecordID></System>
          <EventData><Data Name="LogonType">{type}</Data><Data Name="IpAddress">192.0.2.10</Data>
          <Data Name="TargetUserSid">S-1-0-0</Data><Data Name="TargetUserName">private-user</Data></EventData>
        </Event>
        """;
    private sealed class FakeConsole : IConsolePresenceObserver
    { public ConsolePresenceObservation Capture(DateTime utcNow) => Console(); }
    private sealed class FakeLogons : IRdpLogonObservationSource
    { public void Start() { } public void Stop() { } public void Dispose() { } public RdpLogonBatch Drain(DateTime utcNow) => Batch(); }
    private sealed class FakeWireless : IWirelessInventoryObserver
    { public WirelessInventorySnapshot Capture(DateTime utcNow) => new() { CapturedAtUtc = utcNow,
        WifiAvailability = SecurityObservationAvailability.Unavailable, BluetoothAvailability = SecurityObservationAvailability.Unavailable,
        Limitations = ["Fixture source unavailable."] }; }
}
