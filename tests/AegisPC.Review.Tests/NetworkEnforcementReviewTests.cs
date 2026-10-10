using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using AegisPC.Contracts.Network;
using AegisPC.Security.Network;
using AegisPC.Service.Network;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Inert backend and observation tests; no Windows filter is installed on the host.</summary>
public sealed class NetworkEnforcementReviewTests
{
    [Fact]
    public void RecordedOnlyAndRepeatedRequestsNeverReportBlocked()
    {
        using var service = new WfpEnforcementService(new Backend { IsAvailable = false });
        Assert.Equal(WfpEnforcementOutcome.RecordedOnly, service.BlockOutboundIpWithReceipt("198.51.100.1").Outcome);
        Assert.False(service.BlockOutboundIp("198.51.100.1"));
        Assert.Equal(0, service.ActiveBlockFilterCount);
        Assert.Equal(1, service.RecordedRequestCount);
        Assert.False(service.UnblockIp("198.51.100.1"));
    }

    [Fact]
    public void FailedNativeAddIsRetriedInsteadOfBecomingAlreadyApplied()
    {
        var backend = new Backend { AddError = 5 };
        using var service = new WfpEnforcementService(backend);
        Assert.False(service.BlockOutboundIp("198.51.100.2"));
        Assert.False(service.BlockOutboundIp("198.51.100.2"));
        Assert.Equal(2, backend.AddCalls);
        Assert.Equal(0, service.ActiveBlockFilterCount);
        backend.AddError = 0;
        Assert.True(service.BlockOutboundIp("198.51.100.2"));
        Assert.Equal(WfpEnforcementOutcome.AlreadyApplied, service.BlockOutboundIpWithReceipt("198.51.100.2").Outcome);
    }

    [Fact]
    public void FailedRemovalRetainsFilterForRollbackRetry()
    {
        var backend = new Backend { DeleteError = 5 };
        using var service = new WfpEnforcementService(backend);
        Assert.True(service.BlockOutboundIp("198.51.100.3"));
        Assert.False(service.UnblockIp("198.51.100.3"));
        Assert.Equal(1, service.ActiveBlockFilterCount);
        backend.DeleteError = 0;
        Assert.True(service.UnblockIp("198.51.100.3"));
        Assert.Equal(0, service.ActiveBlockFilterCount);
    }

    [Fact]
    public void ZeroFilterIdAndUnsupportedAddressAreNotApplied()
    {
        var backend = new Backend { FilterId = 0 };
        using var service = new WfpEnforcementService(backend);
        Assert.False(service.BlockOutboundIp("198.51.100.4"));
        Assert.Equal(WfpEnforcementOutcome.Unsupported, service.BlockOutboundIpWithReceipt("2001:db8::1").Outcome);
        Assert.Equal(WfpEnforcementOutcome.Failed, service.BlockOutboundIpWithReceipt("bad address").Outcome);
    }

    [Fact]
    public void RecordedRequestMemoryIsBounded()
    {
        using var service = new WfpEnforcementService(new Backend { IsAvailable = false });
        for (int i = 1; i <= 512; i++) service.BlockOutboundIp($"198.51.{i / 256}.{i % 256}");
        Assert.InRange(service.RecordedRequestCount, 0, 256);
        Assert.Equal(0, service.ActiveBlockFilterCount);
    }

    [Fact]
    public void NativeFilterAbiUsesInlineSixteenByteUnionAndValidWeight()
    {
        var backend = typeof(WfpEnforcementService).Assembly.GetType("AegisPC.Service.Network.WfpNativeBackend")!;
        var filter = backend.GetNestedType("Filter", BindingFlags.NonPublic)!;
        var context = backend.GetNestedType("Context", BindingFlags.NonPublic)!;
        Assert.Equal(16, Marshal.SizeOf(context));
        if (Environment.Is64BitProcess)
        {
            Assert.Equal(200, Marshal.SizeOf(filter));
            Assert.Equal(176, Marshal.OffsetOf(filter, "Id").ToInt32());
        }
    }

    [Fact]
    public void ProcessNameAloneDoesNotGenerateMalwareEvidence()
    {
        var correlator = new NetworkProcessCorrelator();
        var verdict = correlator.CorrelateFlow(Flow(0));
        Assert.False(verdict.IsSuspicious);
        Assert.False(verdict.IsC2Beaconing);
        Assert.Empty(verdict.Evidences);
    }

    [Fact]
    public void PeriodicUpdaterIsReviewOnlyNotConfirmedC2()
    {
        var correlator = new NetworkProcessCorrelator();
        var flows = Enumerable.Range(0, 5).Select(Flow).ToArray();
        foreach (var flow in flows) correlator.IngestNetworkFlow(flow);
        var verdict = correlator.CorrelateFlow(flows[^1]);
        Assert.True(verdict.HasPeriodicPattern);
        Assert.False(verdict.IsC2Beaconing);
        Assert.InRange(verdict.RiskScore, 1, 35);
    }

    [Fact]
    public void MissingLifetimeAndReusedPidDoNotMixBehavior()
    {
        var correlator = new NetworkProcessCorrelator();
        var flows = Enumerable.Range(0, 5).Select(Flow).ToArray();
        foreach (var flow in flows) { flow.ProcessStartedAtUtc = null; correlator.IngestNetworkFlow(flow); }
        Assert.False(correlator.CorrelateFlow(Flow(5)).HasPeriodicPattern);
        var other = new NetworkProcessCorrelator();
        foreach (var flow in Enumerable.Range(0, 5).Select(Flow))
        { flow.BootId = $"boot-{flow.EventId}"; other.IngestNetworkFlow(flow); }
        Assert.False(other.CorrelateFlow(Flow(5)).HasPeriodicPattern);
    }

    [Fact]
    public void DuplicateAndMutableInputCannotMultiplyHistory()
    {
        var correlator = new NetworkProcessCorrelator();
        var flow = Flow(0);
        for (int i = 0; i < 8; i++) correlator.IngestNetworkFlow(flow);
        flow.ProcessName = "modified.exe";
        var history = correlator.GetProcessFlowHistory(42, TimeSpan.FromMinutes(5));
        Assert.Single(history);
        Assert.Equal("powershell.exe", history[0].ProcessName);
        history[0].RemoteAddress = "changed";
        Assert.Equal("198.51.100.10", correlator.GetProcessFlowHistory(42, TimeSpan.FromMinutes(5))[0].RemoteAddress);
    }

    [Theory]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.254", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("fc00::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("::ffff:192.168.1.1", true)]
    [InlineData("2001:db8::1", false)]
    public void AddressScopeIsCidrBased(string address, bool local)
        => Assert.Equal(local, NetworkAddressScope.IsLocalOrPrivate(address));

    private static readonly DateTime BaseTime = DateTime.UtcNow.AddSeconds(-45);
    private static NetworkFlowEvent Flow(int index) => new()
    {
        EventId = $"event-{index}", ProcessId = 42, ProcessName = "powershell.exe", BootId = "test-boot",
        ProcessStartedAtUtc = BaseTime.AddMinutes(-1), RemoteAddress = "198.51.100.10", RemotePort = 443,
        TimestampUtc = BaseTime.AddSeconds(index * 5)
    };
    private sealed class Backend : IWfpNativeBackend
    {
        public bool IsSupported => true;
        public bool IsAvailable { get; set; } = true;
        public uint AddError { get; set; }
        public uint DeleteError { get; set; }
        public ulong FilterId { get; set; } = 12;
        public int AddCalls { get; private set; }
        public (uint Error, ulong FilterId) AddOutboundFilter(IPAddress address, string reason)
        { AddCalls++; return (AddError, FilterId); }
        public uint DeleteFilter(ulong filterId) => DeleteError;
        public void Dispose() { }
    }
}
