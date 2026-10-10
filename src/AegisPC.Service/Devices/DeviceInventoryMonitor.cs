using System.Threading.Channels;
using AegisPC.Contracts.Devices;
using AegisPC.Core.Models.Devices;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Devices;

/// <summary>Register-first user-mode discovery and cancellable initial media scanning orchestration.</summary>
public sealed class DeviceInventoryMonitor : IDeviceInventoryMonitor, IAsyncDisposable
{
    private readonly IDeviceInventorySource _source;
    private readonly Func<MediaVolumeSession, CancellationToken, Task>? _onReadyVolume;
    private readonly Func<MediaVolumeSession, Task>? _onRemovedVolume;
    private readonly ILogger<DeviceInventoryMonitor>? _logger;
    private readonly DeviceInventoryMonitorOptions _options;
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private readonly object _publishGate = new();
    private readonly Dictionary<string, ActiveVolume> _active = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _eligible = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Guid> _mediaFailures = new(StringComparer.OrdinalIgnoreCase);
    private DeviceInventorySnapshot _snapshot = new([], [], false, "Device discovery has not started.");
    private CancellationTokenSource? _runCancellation;
    private IDisposable? _registration;
    private Channel<DeviceDiscoverySignal>? _signals;
    private Task? _loop;
    private bool _baselineEstablished;
    private int _readinessRetries;
    private int _running;
    private int _disposed;
    private long _droppedSignals;
    private string? _callbackFailure;

    /// <summary>Constructs an inert monitor; subscriptions and metadata queries start only in StartAsync.</summary>
    public DeviceInventoryMonitor(IDeviceInventorySource source,
        Func<MediaVolumeSession, CancellationToken, Task>? onReadyVolume = null,
        Func<MediaVolumeSession, Task>? onRemovedVolume = null,
        ILogger<DeviceInventoryMonitor>? logger = null, DeviceInventoryMonitorOptions? options = null)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _onReadyVolume = onReadyVolume;
        _onRemovedVolume = onRemovedVolume;
        _logger = logger;
        var suppliedOptions = options ?? new DeviceInventoryMonitorOptions();
        _options = suppliedOptions with { ReadinessRetryDelays = Array.AsReadOnly(suppliedOptions.ReadinessRetryDelays.ToArray()) };
        _options.Validate();
    }

    /// <inheritdoc />
    public bool IsRunning => Volatile.Read(ref _running) != 0;
    /// <inheritdoc />
    public DeviceInventorySnapshot CurrentSnapshot => Volatile.Read(ref _snapshot);
    /// <inheritdoc />
    public event Action<DeviceInventorySnapshot>? SnapshotChanged;

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsRunning) return;
            await CleanupAsync().ConfigureAwait(false);
            _known.Clear();
            _eligible.Clear();
            _baselineEstablished = false;
            _readinessRetries = 0;
            _callbackFailure = null;
            _mediaFailures.Clear();
            Interlocked.Exchange(ref _droppedSignals, 0);
            var run = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _runCancellation = run;
            var signals = Channel.CreateBounded<DeviceDiscoverySignal>(new BoundedChannelOptions(_options.SignalCapacity)
            { SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.Wait });
            _signals = signals;
            try
            {
                // The callback only enqueues. Register before the first snapshot to avoid an arrival gap.
                _registration = _source.Subscribe(signal =>
                {
                    if (!run.IsCancellationRequested && !signals.Writer.TryWrite(signal))
                        Interlocked.Increment(ref _droppedSignals);
                });
                Volatile.Write(ref _running, 1);
                await CaptureAndApplyAsync(run.Token).ConfigureAwait(false);
                _loop = RunAsync(signals.Reader, run.Token);
            }
            catch (OperationCanceledException)
            {
                await CleanupAsync().ConfigureAwait(false);
                throw;
            }
            catch (Exception exception)
            {
                _logger?.LogWarning(exception, "Device notification registration or startup failed.");
                await CleanupAsync().ConfigureAwait(false);
                Publish(new(CurrentSnapshot.Devices, CurrentSnapshot.Volumes, false,
                    "Device discovery startup failed; new device coverage is unavailable.", presenceComplete: false));
            }
        }
        finally { _lifecycle.Release(); }
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        try { _runCancellation?.Cancel(); }
        catch (ObjectDisposedException) { } // A concurrent lifecycle cleanup already cancelled this generation.
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await CleanupAsync().ConfigureAwait(false);
            Publish(new(CurrentSnapshot.Devices, CurrentSnapshot.Volumes, false,
                "Device discovery is stopped; the inventory is stale.", presenceComplete: false));
        }
        finally { _lifecycle.Release(); }
    }

    private async Task RunAsync(ChannelReader<DeviceDiscoverySignal> reader, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                bool awaitingReady = CurrentSnapshot.Volumes.Any(v => _eligible.Contains(v.VolumeGuid) && !v.IsReady);
                TimeSpan delay = awaitingReady && _readinessRetries < _options.ReadinessRetryDelays.Count
                    ? _options.ReadinessRetryDelays[_readinessRetries] : _options.ReconcileInterval;
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
                wait.CancelAfter(delay);
                bool eventArrived = false;
                try { eventArrived = await reader.WaitToReadAsync(wait.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
                ct.ThrowIfCancellationRequested();
                if (!eventArrived) _readinessRetries++;
                else
                {
                    _readinessRetries = 0;
                    while (reader.TryRead(out var signal))
                        if (signal.Kind == DeviceDiscoverySignalKind.Removal)
                            await CancelRemovedInterfaceAsync(signal.InterfacePath).ConfigureAwait(false);
                }
                await CaptureAndApplyAsync(ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception exception)
        {
            _logger?.LogWarning(exception, "Device observation processing failed.");
            Publish(new(CurrentSnapshot.Devices, CurrentSnapshot.Volumes, false,
                "Device observation processing failed; the inventory is stale.", presenceComplete: false));
        }
        finally
        {
            Volatile.Write(ref _running, 0);
            foreach (var active in _active.Values) active.Cancellation.Cancel();
            DisposeRegistration();
        }
    }

    private async Task CaptureAndApplyAsync(CancellationToken ct)
    {
        DeviceInventorySnapshot next;
        try { next = await _source.CaptureAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception)
        {
            _logger?.LogWarning(exception, "Device inventory capture failed.");
            Publish(new(CurrentSnapshot.Devices, CurrentSnapshot.Volumes, false,
                "Device inventory capture failed; prior membership is retained as stale.", presenceComplete: false));
            return;
        }
        ct.ThrowIfCancellationRequested();
        var present = next.Volumes.Select(v => v.VolumeGuid).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var key in _active.Where(pair => Volatile.Read(ref pair.Value.Failed) != 0).Select(pair => pair.Key).ToArray())
            await RemoveAsync(key).ConfigureAwait(false);
        if (next.PresenceComplete)
        {
            foreach (var key in _active.Keys.Where(k => !present.Contains(k)).ToArray())
                await RemoveAsync(key).ConfigureAwait(false);
            _known.IntersectWith(present);
            _eligible.IntersectWith(present);
            foreach (var key in _mediaFailures.Keys.Where(key => !present.Contains(key))) _mediaFailures.TryRemove(key, out _);
        }
        bool budgetExceeded = false;
        foreach (var volume in next.Volumes)
        {
            ct.ThrowIfCancellationRequested();
            bool newlyPresent = !_known.Contains(volume.VolumeGuid);
            if (volume.UsbAssociation == UsbAssociation.Usb || volume.DriveType == DriveType.Removable ||
                (_baselineEstablished && newlyPresent)) _eligible.Add(volume.VolumeGuid);
            _known.Add(volume.VolumeGuid);
            if (_active.TryGetValue(volume.VolumeGuid, out var active) && active.Fingerprint != Fingerprint(volume))
                await RemoveAsync(volume.VolumeGuid).ConfigureAwait(false);
            if (!_eligible.Contains(volume.VolumeGuid) || !volume.IsReady || string.IsNullOrWhiteSpace(volume.VolumeGuid) ||
                _active.ContainsKey(volume.VolumeGuid)) continue;
            if (_active.Count >= _options.MaximumActiveVolumes) { budgetExceeded = true; continue; }
            var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var session = new MediaVolumeSession { Volume = volume, InsertionCancellation = cancellation.Token };
            var inserted = new ActiveVolume(session, cancellation, Fingerprint(volume));
            _active.Add(volume.VolumeGuid, inserted);
            inserted.Work = Task.Run(() => InvokeReadyAsync(inserted));
        }
        // Partial membership must not turn pre-existing internal disks into later "insertions".
        // USB/removable volumes remain eligible even before this baseline is established.
        if (next.PresenceComplete) _baselineEstablished = true;
        long dropped = Interlocked.Exchange(ref _droppedSignals, 0);
        string? failure = dropped > 0 ? $"Device notification queue lost {dropped} signal(s); inventory reconciled, event history is incomplete." :
            budgetExceeded ? "The active media budget was reached; some attached media is not monitored." :
            Volatile.Read(ref _callbackFailure) ?? (!_mediaFailures.IsEmpty ? "Initial media observation or scanning failed; coverage is incomplete." : next.FailureReason);
        Publish(new(next.Devices, next.Volumes, next.IsComplete && failure == null, failure,
            next.CapturedAtUtc, next.PresenceComplete));
    }

    private async Task InvokeReadyAsync(ActiveVolume active)
    {
        var session = active.Session;
        try
        {
            session.InsertionCancellation.ThrowIfCancellationRequested();
            if (_onReadyVolume != null)
                await _onReadyVolume(session, session.InsertionCancellation).ConfigureAwait(false);
            ((ICollection<KeyValuePair<string, Guid>>)_mediaFailures).Remove(new(session.Volume.VolumeGuid, session.Generation));
        }
        catch (OperationCanceledException) when (session.InsertionCancellation.IsCancellationRequested) { }
        catch (Exception exception)
        {
            Volatile.Write(ref active.Failed, 1);
            _mediaFailures[session.Volume.VolumeGuid] = session.Generation;
            _logger?.LogWarning(exception, "Initial media callback failed for generation {Generation}.", session.Generation);
            Publish(new(CurrentSnapshot.Devices, CurrentSnapshot.Volumes, false,
                "Initial media observation or scanning failed; coverage is incomplete.", presenceComplete: CurrentSnapshot.PresenceComplete));
        }
    }

    private async Task CancelRemovedInterfaceAsync(string path)
    {
        var ids = CurrentSnapshot.Devices.Where(d => string.Equals(d.InterfacePath, path, StringComparison.OrdinalIgnoreCase))
            .Select(d => d.InstanceId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var key in _active.Where(p => p.Value.Session.Volume.DeviceInstanceIds.Any(ids.Contains)).Select(p => p.Key).ToArray())
        {
            await RemoveAsync(key).ConfigureAwait(false);
            _known.Remove(key);
            _eligible.Remove(key);
        }
    }

    private async Task RemoveAsync(string key)
    {
        if (!_active.Remove(key, out var active)) return;
        active.Cancellation.Cancel();
        try { await active.Work.WaitAsync(_options.CallbackStopTimeout).ConfigureAwait(false); }
        catch (TimeoutException)
        {
            Volatile.Write(ref _callbackFailure, "A removed media callback did not stop within its budget.");
            _logger?.LogWarning("Media callback exceeded its stop budget for generation {Generation}.", active.Session.Generation);
        }
        try
        {
            if (_onRemovedVolume != null)
                await _onRemovedVolume(active.Session).WaitAsync(_options.CallbackStopTimeout).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Volatile.Write(ref _callbackFailure, "A media watcher could not be detached cleanly.");
            _logger?.LogWarning(exception, "Media removal callback failed for generation {Generation}.", active.Session.Generation);
        }
        if (active.Work.IsCompleted) active.Cancellation.Dispose();
        else _ = DisposeAfterCompletionAsync(active);
    }

    private static async Task DisposeAfterCompletionAsync(ActiveVolume active)
    {
        try { await active.Work.ConfigureAwait(false); }
        finally { active.Cancellation.Dispose(); }
    }

    private async Task CleanupAsync()
    {
        Volatile.Write(ref _running, 0);
        _runCancellation?.Cancel();
        DisposeRegistration(); // Never executed on a native notification callback thread.
        _signals?.Writer.TryComplete();
        if (_loop != null) await _loop.ConfigureAwait(false);
        _loop = null;
        foreach (var key in _active.Keys.ToArray()) await RemoveAsync(key).ConfigureAwait(false);
        _runCancellation?.Dispose();
        _runCancellation = null;
        _signals = null;
    }

    private void DisposeRegistration()
    {
        try { Interlocked.Exchange(ref _registration, null)?.Dispose(); }
        catch (Exception exception)
        {
            Volatile.Write(ref _callbackFailure, "Device notification unregistration failed.");
            _logger?.LogWarning(exception, "Device notification unregistration failed.");
        }
    }

    private void Publish(DeviceInventorySnapshot snapshot)
    {
        lock (_publishGate)
        {
            // An asynchronous scan failure must not be overwritten by a concurrently finishing inventory capture.
            if (snapshot.IsComplete && !_mediaFailures.IsEmpty)
                snapshot = new(snapshot.Devices, snapshot.Volumes, false,
                    "Initial media observation or scanning failed; coverage is incomplete.", snapshot.CapturedAtUtc, snapshot.PresenceComplete);
            Volatile.Write(ref _snapshot, snapshot);
        }
        var handlers = SnapshotChanged;
        if (handlers == null) return;
        foreach (Action<DeviceInventorySnapshot> handler in handlers.GetInvocationList())
        {
            try { handler(snapshot); }
            catch (Exception exception) { _logger?.LogWarning(exception, "A device inventory observer failed."); }
        }
    }

    private static string Fingerprint(MediaVolumeMetadata volume) => string.Join("|", volume.DeviceInstanceIds
        .OrderBy(v => v, StringComparer.OrdinalIgnoreCase)) + ":" + string.Join(",", volume.DiskNumbers.Order());

    /// <summary>Unregisters notifications and cancels owned media generations.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        await StopAsync().ConfigureAwait(false);
        _lifecycle.Dispose();
    }

    private sealed class ActiveVolume(MediaVolumeSession session, CancellationTokenSource cancellation, string fingerprint)
    {
        internal MediaVolumeSession Session { get; } = session;
        internal CancellationTokenSource Cancellation { get; } = cancellation;
        internal string Fingerprint { get; } = fingerprint;
        internal Task Work { get; set; } = Task.CompletedTask;
        internal int Failed;
    }
}
