using System.Buffers.Binary;
using System.IO;
using AegisPC.Contracts.Devices;
using AegisPC.Core.Models.Devices;
using AegisPC.Service.Devices;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert descriptor and lifecycle infrastructure tests; no native devices or malware are opened.</summary>
public sealed class DeviceDiscoveryTests
{
    /// <summary>Storage type is rejected when either native size claim exceeds the available descriptor.</summary>
    [Fact]
    public void StorageDescriptor_RejectsTruncatedAndOversizedClaims()
    {
        var descriptor = new byte[36];
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(4), 36);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(28), 7);
        Assert.Equal((uint)7, DeviceDescriptorDecoder.ReadStorageBusType(descriptor, 36));
        Assert.Null(DeviceDescriptorDecoder.ReadStorageBusType(descriptor, 35));
        Assert.Null(DeviceDescriptorDecoder.ReadStorageBusType(descriptor, 37));
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(4), 65537);
        Assert.Null(DeviceDescriptorDecoder.ReadStorageBusType(descriptor, 36));
    }

    /// <summary>UASP/SCSI disks remain USB-associated when an observed parent provides USB transport evidence.</summary>
    [Fact]
    public void TransportClassification_UsesParentEvidenceAndPreservesUnknown()
    {
        Assert.Equal(UsbAssociation.Usb, DeviceDescriptorDecoder.ClassifyUsb(1, true, true));
        Assert.Equal(UsbAssociation.Usb, DeviceDescriptorDecoder.ClassifyUsb(7, false, false));
        Assert.Equal(UsbAssociation.NotUsb, DeviceDescriptorDecoder.ClassifyUsb(17, false, true));
        Assert.Equal(UsbAssociation.Unknown, DeviceDescriptorDecoder.ClassifyUsb(null, false, true));
        Assert.Equal(UsbAssociation.Unknown, DeviceDescriptorDecoder.ClassifyUsb(1, false, false));
    }

    /// <summary>Extent count, alignment and returned length are bounded before any disk number is decoded.</summary>
    [Fact]
    public void VolumeExtents_ValidateCountAndNativeReturnLength()
    {
        var buffer = new byte[56];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, 2);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(8), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(32), 1);
        Assert.Equal(new uint[] { 1, 3 }, DeviceDescriptorDecoder.ReadVolumeDiskNumbers(buffer, 56));
        Assert.Null(DeviceDescriptorDecoder.ReadVolumeDiskNumbers(buffer, 55));
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, 129);
        Assert.Null(DeviceDescriptorDecoder.ReadVolumeDiskNumbers(buffer, 56));
    }

    /// <summary>All nested collections are copied before an inventory is published to observers.</summary>
    [Fact]
    public void Snapshot_DoesNotExposeMutableProducerCollections()
    {
        var mounts = new List<string> { "R:\\" };
        var parents = new List<string> { "USB\\fixture" };
        var ids = new List<string> { "disk-fixture" };
        var numbers = new List<uint> { 2 };
        var snapshot = new DeviceInventorySnapshot([new DeviceMetadata { AncestorInstanceIds = parents }],
            [new MediaVolumeMetadata { MountPaths = mounts, DeviceInstanceIds = ids, DiskNumbers = numbers }], true);
        mounts.Clear(); parents.Clear(); ids.Clear(); numbers.Clear();
        Assert.Single(snapshot.Volumes[0].MountPaths);
        Assert.Single(snapshot.Volumes[0].DeviceInstanceIds);
        Assert.Single(snapshot.Volumes[0].DiskNumbers);
        Assert.Single(snapshot.Devices[0].AncestorInstanceIds);
    }

    /// <summary>Notifications are registered before enumeration and an already-mounted fixed USB disk is inspected.</summary>
    [Fact]
    public async Task Startup_RegistersBeforeCaptureAndInspectsExistingFixedUsb()
    {
        var source = new FixtureSource(Snapshot(Volume()));
        var started = new TaskCompletionSource<MediaVolumeSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, (session, _) => { started.TrySetResult(session); return Task.CompletedTask; });
        await monitor.StartAsync();
        var generation = await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(new[] { "subscribe", "capture" }, source.Operations.Take(2));
        Assert.Equal(DriveType.Fixed, generation.Volume.DriveType);
        Assert.True(monitor.IsRunning);
        await monitor.StopAsync();
        Assert.True(generation.InsertionCancellation.IsCancellationRequested);
        Assert.Equal(1, source.DisposeCount);
    }

    /// <summary>Repeated readiness or property snapshots do not restart a completed initial inspection.</summary>
    [Fact]
    public async Task Reconcile_DoesNotEnqueueTheSameGenerationTwice()
    {
        var source = new FixtureSource(Snapshot(Volume()));
        int starts = 0;
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, (_, _) => { Interlocked.Increment(ref starts); started.TrySetResult(); return Task.CompletedTask; });
        await monitor.StartAsync();
        await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await ReconcileAsync(source, monitor, source.Snapshot);
        await ReconcileAsync(source, monitor, source.Snapshot);
        Assert.Equal(1, Volatile.Read(ref starts));
    }

    /// <summary>A media readiness transition starts exactly one generation rather than treating unreadable media as clean.</summary>
    [Fact]
    public async Task NotReadyMedia_IsRetriedAndStartsOnlyWhenReadable()
    {
        var source = new FixtureSource(Snapshot(Volume() with { IsReady = false, Limitation = "not ready" }));
        var started = new TaskCompletionSource<MediaVolumeSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, (session, _) => { started.TrySetResult(session); return Task.CompletedTask; });
        await monitor.StartAsync();
        Assert.False(started.Task.IsCompleted);
        Assert.False(monitor.CurrentSnapshot.IsComplete);
        await ReconcileAsync(source, monitor, Snapshot(Volume()));
        Assert.True((await started.Task.WaitAsync(TimeSpan.FromSeconds(3))).Volume.IsReady);
    }

    /// <summary>Removal cancels scan work before its watcher removal callback is invoked.</summary>
    [Fact]
    public async Task Removal_CancelsBeforeDetachingAndNewInsertionGetsNewGeneration()
    {
        var source = new FixtureSource(Snapshot(Volume()));
        var starts = new System.Collections.Concurrent.ConcurrentQueue<MediaVolumeSession>();
        var initial = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var removed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, async (session, token) =>
        {
            starts.Enqueue(session);
            initial.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
        }, session =>
        {
            Assert.True(session.InsertionCancellation.IsCancellationRequested);
            removed.TrySetResult();
            return Task.CompletedTask;
        });
        await monitor.StartAsync();
        await initial.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await ReconcileAsync(source, monitor, Snapshot());
        await removed.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await ReconcileAsync(source, monitor, Snapshot(Volume()));
        await WaitUntilAsync(() => starts.Count == 2);
        Assert.NotEqual(starts.ElementAt(0).Generation, starts.ElementAt(1).Generation);
    }

    /// <summary>An incomplete empty inventory retains prior membership instead of falsely removing active media.</summary>
    [Fact]
    public async Task PartialCapture_DoesNotCancelExistingVolume()
    {
        var source = new FixtureSource(Snapshot(Volume()));
        var initial = new TaskCompletionSource<MediaVolumeSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, (session, _) => { initial.TrySetResult(session); return Task.CompletedTask; });
        await monitor.StartAsync();
        var session = await initial.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await ReconcileAsync(source, monitor, new DeviceInventorySnapshot([], [], false, "query unavailable"));
        Assert.False(session.InsertionCancellation.IsCancellationRequested);
        Assert.False(monitor.CurrentSnapshot.IsComplete);
        await ReconcileAsync(source, monitor, Snapshot());
        Assert.True(session.InsertionCancellation.IsCancellationRequested);
    }

    /// <summary>Complete membership can remove a volume even when unrelated HID properties are unavailable.</summary>
    [Fact]
    public async Task MissingMetadata_DoesNotPreventKnownRemoval()
    {
        var source = new FixtureSource(Snapshot(Volume()));
        var initial = new TaskCompletionSource<MediaVolumeSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, (session, _) => { initial.TrySetResult(session); return Task.CompletedTask; });
        await monitor.StartAsync();
        var session = await initial.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await ReconcileAsync(source, monitor, new DeviceInventorySnapshot([], [], false, "HID query unavailable", presenceComplete: true));
        Assert.True(session.InsertionCancellation.IsCancellationRequested);
        Assert.False(monitor.CurrentSnapshot.IsComplete);
    }

    /// <summary>Registration failure is visible and cannot produce an active or complete discovery status.</summary>
    [Fact]
    public async Task RegistrationFailure_RemainsVisibleAndInactive()
    {
        var source = new FixtureSource(Snapshot()) { FailRegistration = true };
        await using var monitor = Monitor(source);
        await monitor.StartAsync();
        Assert.False(monitor.IsRunning);
        Assert.False(monitor.CurrentSnapshot.IsComplete);
        Assert.Contains("startup failed", monitor.CurrentSnapshot.FailureReason ?? string.Empty);
    }

    /// <summary>Existing non-USB system disks and HID-only metadata do not trigger a whole-system initial media scan.</summary>
    [Fact]
    public async Task Startup_ExistingInternalDiskAndHidDoNotBecomeMediaScans()
    {
        var volume = Volume() with { UsbAssociation = UsbAssociation.NotUsb };
        var source = new FixtureSource(new DeviceInventorySnapshot([new DeviceMetadata { Functions = DeviceFunction.Keyboard | DeviceFunction.Hid }], [volume], true));
        int starts = 0;
        await using var monitor = Monitor(source, (_, _) => { Interlocked.Increment(ref starts); return Task.CompletedTask; });
        await monitor.StartAsync();
        await ReconcileAsync(source, monitor, source.Snapshot);
        Assert.Equal(0, Volatile.Read(ref starts));
        Assert.Single(monitor.CurrentSnapshot.Devices);
    }

    /// <summary>A newly arriving local volume is inspected even when the transport query remains unknown.</summary>
    [Fact]
    public async Task NewlyArrivingUnknownTransport_IsNotExcludedFromScanning()
    {
        var source = new FixtureSource(Snapshot());
        var started = new TaskCompletionSource<MediaVolumeSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, (session, _) => { started.TrySetResult(session); return Task.CompletedTask; });
        await monitor.StartAsync();
        await ReconcileAsync(source, monitor, Snapshot(Volume() with { UsbAssociation = UsbAssociation.Unknown, Limitation = "transport unknown" }));
        Assert.Equal(UsbAssociation.Unknown, (await started.Task.WaitAsync(TimeSpan.FromSeconds(3))).Volume.UsbAssociation);
        Assert.False(monitor.CurrentSnapshot.IsComplete);
    }

    /// <summary>GUID-only media is inspectable without relying on a drive letter or mounting it.</summary>
    [Fact]
    public async Task ReadyGuidOnlyUsbVolume_IsInspectedWithoutDriveLetter()
    {
        var source = new FixtureSource(Snapshot(Volume() with { MountPaths = [] }));
        var started = new TaskCompletionSource<MediaVolumeSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, (session, _) => { started.TrySetResult(session); return Task.CompletedTask; });
        await monitor.StartAsync();
        Assert.Empty((await started.Task.WaitAsync(TimeSpan.FromSeconds(3))).Volume.MountPaths);
    }

    /// <summary>A failed initial callback is retried on reconciliation instead of retaining a permanently inert generation.</summary>
    [Fact]
    public async Task ReadyCallbackFailure_IsVisibleAndRetryable()
    {
        var source = new FixtureSource(Snapshot(Volume()));
        int starts = 0;
        var failed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var recovered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, (_, _) =>
        {
            if (Interlocked.Increment(ref starts) == 1) throw new InvalidOperationException("fixture scan failure");
            recovered.TrySetResult();
            return Task.CompletedTask;
        });
        monitor.SnapshotChanged += snapshot =>
        {
            if (snapshot.FailureReason?.Contains("Initial media", StringComparison.Ordinal) == true) failed.TrySetResult();
        };
        await monitor.StartAsync();
        await failed.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.False(monitor.CurrentSnapshot.IsComplete);
        await ReconcileAsync(source, monitor, Snapshot(Volume()));
        await recovered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(2, Volatile.Read(ref starts));
    }

    /// <summary>Changing the physical identity under the same volume path cancels the old generation before starting another.</summary>
    [Fact]
    public async Task ReusedVolumePath_CancelsPriorPhysicalIdentity()
    {
        var source = new FixtureSource(Snapshot(Volume()));
        var started = new System.Collections.Concurrent.ConcurrentQueue<MediaVolumeSession>();
        await using var monitor = Monitor(source, (session, _) => { started.Enqueue(session); return Task.CompletedTask; });
        await monitor.StartAsync();
        await WaitUntilAsync(() => started.Count == 1);
        await ReconcileAsync(source, monitor, Snapshot(Volume() with { DeviceInstanceIds = ["replacement-fixture"], DiskNumbers = [3] }));
        await WaitUntilAsync(() => started.Count == 2);
        Assert.True(started.ElementAt(0).InsertionCancellation.IsCancellationRequested);
        Assert.NotEqual(started.ElementAt(0).Generation, started.ElementAt(1).Generation);
    }

    /// <summary>Changing drive letters cannot restart the same volume GUID and physical insertion's completed inspection.</summary>
    [Fact]
    public async Task MountPathOnlyChange_DoesNotRequeueTheSamePhysicalInsertion()
    {
        var source = new FixtureSource(Snapshot(Volume()));
        int starts = 0;
        var initial = new TaskCompletionSource<MediaVolumeSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, (session, _) =>
        { Interlocked.Increment(ref starts); initial.TrySetResult(session); return Task.CompletedTask; });
        await monitor.StartAsync();
        var session = await initial.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await ReconcileAsync(source, monitor, Snapshot(Volume() with { MountPaths = ["S:\\"] }));
        Assert.Equal(1, Volatile.Read(ref starts));
        Assert.False(session.InsertionCancellation.IsCancellationRequested);
        Assert.Equal("S:\\", monitor.CurrentSnapshot.Volumes[0].MountPaths.Single());
    }

    private static DeviceInventoryMonitor Monitor(FixtureSource source,
        Func<MediaVolumeSession, CancellationToken, Task>? ready = null, Func<MediaVolumeSession, Task>? removed = null) =>
        new(source, ready, removed, options: new DeviceInventoryMonitorOptions
        { ReconcileInterval = TimeSpan.FromMinutes(1), ReadinessRetryDelays = [TimeSpan.FromMinutes(1)] });

    /// <summary>Incomplete startup membership cannot misclassify an existing internal fixed disk as newly inserted media.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PartialStartup_DoesNotAutoScanInternalDisksWhenMembershipRecovers(bool includesOneDisk)
    {
        var internalDisk = Volume() with { UsbAssociation = UsbAssociation.NotUsb, StorageBusType = 17 };
        var initial = new DeviceInventorySnapshot([], includesOneDisk ? [internalDisk] : [], false,
            "inert incomplete initial membership", presenceComplete: false);
        var source = new FixtureSource(initial);
        int starts = 0;
        var inserted = new TaskCompletionSource<MediaVolumeSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = Monitor(source, (session, _) =>
        { Interlocked.Increment(ref starts); inserted.TrySetResult(session); return Task.CompletedTask; });
        await monitor.StartAsync();
        await ReconcileAsync(source, monitor, Snapshot(internalDisk));
        var eligible = (HashSet<string>)typeof(DeviceInventoryMonitor).GetField("_eligible",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(monitor)!;
        Assert.DoesNotContain(internalDisk.VolumeGuid, eligible);
        Assert.Equal(0, Volatile.Read(ref starts));
        var newDisk = internalDisk with { VolumeGuid = @"\\?\Volume{22222222-2222-2222-2222-222222222222}\", DiskNumbers = [3] };
        await ReconcileAsync(source, monitor, Snapshot(internalDisk, newDisk));
        Assert.Equal(newDisk.VolumeGuid, (await inserted.Task.WaitAsync(TimeSpan.FromSeconds(3))).Volume.VolumeGuid);
        Assert.Equal(1, Volatile.Read(ref starts));
    }

    private static MediaVolumeMetadata Volume() => new()
    {
        VolumeGuid = "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\", MountPaths = ["R:\\"],
        DiskNumbers = [2], DeviceInstanceIds = ["disk-fixture"], IsReady = true,
        DriveType = DriveType.Fixed, StorageBusType = 7, UsbAssociation = UsbAssociation.Usb
    };

    private static DeviceInventorySnapshot Snapshot(params MediaVolumeMetadata[] volumes) =>
        new([], volumes, volumes.All(v => v.Limitation == null), presenceComplete: true);

    private static async Task ReconcileAsync(FixtureSource source, DeviceInventoryMonitor monitor, DeviceInventorySnapshot next)
    {
        var published = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Changed(DeviceInventorySnapshot snapshot)
        {
            if (snapshot.CapturedAtUtc == next.CapturedAtUtc) published.TrySetResult();
        }
        monitor.SnapshotChanged += Changed;
        try
        {
            source.SetSnapshot(next);
            source.Signal(new DeviceDiscoverySignal { Kind = DeviceDiscoverySignalKind.Reconcile });
            await published.Task.WaitAsync(TimeSpan.FromSeconds(3));
        }
        finally { monitor.SnapshotChanged -= Changed; }
    }

    private static async Task WaitUntilAsync(Func<bool> predicate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!predicate()) await Task.Delay(10, timeout.Token);
    }

    private sealed class FixtureSource(DeviceInventorySnapshot initial) : IDeviceInventorySource
    {
        private DeviceInventorySnapshot _snapshot = initial;
        private Action<DeviceDiscoverySignal>? _onSignal;
        private int _disposeCount;
        internal DeviceInventorySnapshot Snapshot => Volatile.Read(ref _snapshot);
        internal List<string> Operations { get; } = [];
        internal bool FailRegistration { get; init; }
        internal int DisposeCount => Volatile.Read(ref _disposeCount);
        public IDisposable Subscribe(Action<DeviceDiscoverySignal> onSignal)
        {
            Operations.Add("subscribe");
            if (FailRegistration) throw new InvalidOperationException("fixture registration failure");
            _onSignal = onSignal;
            return new Registration(() => { Interlocked.Increment(ref _disposeCount); _onSignal = null; });
        }
        public Task<DeviceInventorySnapshot> CaptureAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Operations.Add("capture");
            return Task.FromResult(Snapshot);
        }
        internal void SetSnapshot(DeviceInventorySnapshot snapshot) => Volatile.Write(ref _snapshot, snapshot);
        internal void Signal(DeviceDiscoverySignal signal) => _onSignal?.Invoke(signal);
    }

    private sealed class Registration(Action disposed) : IDisposable
    {
        private int _disposed;
        public void Dispose() { if (Interlocked.Exchange(ref _disposed, 1) == 0) disposed(); }
    }
}
