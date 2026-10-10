using AegisPC.Contracts.Protection;
using AegisPC.Contracts.Services;
using AegisPC.Service.Workers;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Inert hosted lifecycle tests; no Windows logs, radios, network rules or installed services are accessed.</summary>
public sealed class PassiveObservationLifecycleReviewTests
{
    /// <summary>A failed remote subscription must not prevent independent wireless observation or fault the host worker.</summary>
    [Fact]
    public async Task FailedSubscriptionDoesNotStopWirelessObservation()
    {
        var source = new FakeLogons { ThrowOnStart = true };
        var wireless = new FakeWireless();
        using var worker = Worker(source, new FakeRemote(), wireless);
        await worker.StartAsync(CancellationToken.None);
        await wireless.Observed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(worker.IsObservationLoopRunning);
        Assert.Equal(1, source.Starts);
        Assert.Equal(1, source.Stops);
        await worker.StopAsync(CancellationToken.None);
        Assert.False(worker.IsObservationLoopRunning);
        Assert.True(worker.ExecuteTask!.IsCompletedSuccessfully);
    }

    /// <summary>Unavailable subscriptions are closed for a delayed retry rather than repeatedly opened in one capture cycle.</summary>
    [Fact]
    public async Task UnavailableSubscriptionIsClosedWithoutClaimingEnforcement()
    {
        var source = new FakeLogons();
        var remote = new FakeRemote { Availability = SecurityObservationAvailability.Unavailable };
        var wireless = new FakeWireless();
        using var worker = Worker(source, remote, wireless);
        await worker.StartAsync(CancellationToken.None);
        await wireless.Observed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(1, source.Starts);
        Assert.Equal(1, source.Stops);
        Assert.False(remote.CurrentSnapshot.NativeEnforcementActive);
        await worker.StopAsync(CancellationToken.None);
        Assert.Equal(1, source.Stops);
    }

    /// <summary>Cleanup failure is logged by the worker but must not hide shutdown or create a host exception.</summary>
    [Fact]
    public async Task FailedCleanupDoesNotFaultShutdown()
    {
        var source = new FakeLogons { ThrowOnStop = true };
        var wireless = new FakeWireless();
        using var worker = Worker(source, new FakeRemote(), wireless);
        await worker.StartAsync(CancellationToken.None);
        await wireless.Observed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await worker.StopAsync(CancellationToken.None);
        Assert.Equal(1, source.Stops);
        Assert.False(worker.IsObservationLoopRunning);
        Assert.True(worker.ExecuteTask!.IsCompletedSuccessfully);
    }

    /// <summary>An adapter exception preserves the other layer's capture and schedules subscription recovery without an action.</summary>
    [Fact]
    public async Task FailedRemoteRefreshDoesNotStopOtherLayer()
    {
        var source = new FakeLogons();
        var wireless = new FakeWireless();
        using var worker = Worker(source, new FakeRemote { ThrowOnRefresh = true }, wireless);
        await worker.StartAsync(CancellationToken.None);
        await wireless.Observed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(1, source.Stops);
        await worker.StopAsync(CancellationToken.None);
        Assert.True(worker.ExecuteTask!.IsCompletedSuccessfully);
    }

    private static PassiveSecurityObservationWorker Worker(FakeLogons source, FakeRemote remote, FakeWireless wireless) =>
        new(source, remote, wireless, new FakeSettings(), NullLogger<PassiveSecurityObservationWorker>.Instance);

    private sealed class FakeLogons : IRdpLogonObservationSource
    {
        internal bool ThrowOnStart { get; init; }
        internal bool ThrowOnStop { get; init; }
        internal int Starts { get; private set; }
        internal int Stops { get; private set; }
        public void Start() { Starts++; if (ThrowOnStart) throw new InvalidOperationException("Inert subscription failure"); }
        public void Stop() { Stops++; if (ThrowOnStop) throw new InvalidOperationException("Inert cleanup failure"); }
        public RdpLogonBatch Drain(DateTime utcNow) => new() { CapturedAtUtc = utcNow };
        public void Dispose() { }
    }

    private sealed class FakeRemote : IRemoteProtectionMonitor
    {
        internal bool ThrowOnRefresh { get; init; }
        internal SecurityObservationAvailability Availability { get; init; } = SecurityObservationAvailability.Partial;
        public RemoteProtectionSnapshot CurrentSnapshot { get; private set; } = new();
        public RemoteProtectionSnapshot Refresh(DateTime utcNow)
        {
            if (ThrowOnRefresh) throw new InvalidOperationException("Inert capture failure");
            return CurrentSnapshot = new() { CapturedAtUtc = utcNow, LogonAvailability = Availability };
        }
    }

    private sealed class FakeWireless : IWirelessProtectionMonitor
    {
        internal TaskCompletionSource Observed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public WirelessProtectionSnapshot CurrentSnapshot { get; private set; } = new();
        public WirelessProtectionSnapshot Refresh(DateTime utcNow)
        {
            CurrentSnapshot = new() { Inventory = new() { CapturedAtUtc = utcNow } };
            Observed.TrySetResult();
            return CurrentSnapshot;
        }
    }

    private sealed class FakeSettings : ISettingsService
    {
        public T? GetSetting<T>(string key, T defaultValue) => defaultValue;
        public void SetSetting<T>(string key, T value) => throw new InvalidOperationException("Observation must not write settings");
        public Task SaveAsync(CancellationToken cancellationToken = default) => throw new InvalidOperationException("Observation must not save settings");
        public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
