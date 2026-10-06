using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;
using Microsoft.Extensions.Logging;

namespace AegisPC.App.Services;

/// <summary>
/// Mirrors fresh authenticated-service AI review preferences into local scan settings independently of navigation.
/// One worker consumes one latest-state slot; it never starts protection, sends controls, or treats preferences as Guardian health.
/// </summary>
public sealed class UltronAiServicePreferenceSync : IDisposable, IAsyncDisposable
{
    private readonly IServiceIpcClient _ipc;
    private readonly SettingsService _settings;
    private readonly ILogger<UltronAiServicePreferenceSync>? _logger;
    private readonly object _gate = new();
    private readonly CancellationTokenSource _lifetime = new();
    private Observation? _pending;
    private Task _worker = Task.CompletedTask;
    private TaskCompletionSource? _idle;
    private long _latestSequence;
    private bool _workerRunning;
    private bool _persistencePending;
    private bool _lastPersistedEnabled;
    private bool _disposed;
    private string? _lastSynchronizationError;

    private sealed record Observation(long Sequence, bool? Enabled, DateTime CapturedAtUtc, int ProtocolVersion);

    /// <summary>Returns a safe persistence error, or null after a successful synchronization; it does not expose target paths.</summary>
    public string? LastSynchronizationError => Volatile.Read(ref _lastSynchronizationError);

    /// <summary>Subscribes only to the existing identity-verifying IPC client; settings must already be loaded before construction.</summary>
    public UltronAiServicePreferenceSync(IServiceIpcClient ipc, SettingsService settings,
        ILogger<UltronAiServicePreferenceSync>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(ipc);
        ArgumentNullException.ThrowIfNull(settings);
        _ipc = ipc;
        _settings = settings;
        _lastPersistedEnabled = settings.Current.IsUltronAiEnabled;
        _logger = logger;
        _ipc.StatusChanged += ObserveStatus;
    }

    private void ObserveStatus(ProtectionStatus status)
    {
        if (status == null) return;
        bool observed = ServiceProtectionStatusPolicy.IsVerified(_ipc, status) && status.IsUltronAiEnabled.HasValue;
        // Copy scalar data immediately; mutable event payloads cannot change the queued policy afterward.
        lock (_gate)
        {
            if (_disposed) return;
            _pending = new Observation(++_latestSequence, observed ? status.IsUltronAiEnabled : null,
                status.Health?.CapturedAtUtc ?? default, status.Health?.ProtocolVersion ?? 0);
            if (_workerRunning) return;
            _workerRunning = true;
            _idle = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _worker = Task.Run(RunWorkerAsync);
        }
    }

    /// <summary>Waits for the currently queued observations to settle; it performs no IPC query or new control operation.</summary>
    public Task SynchronizeAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
            return (_idle?.Task ?? Task.CompletedTask).WaitAsync(cancellationToken);
    }

    private async Task RunWorkerAsync()
    {
        while (true)
        {
            Observation observation;
            lock (_gate)
            {
                if (_disposed || _pending == null)
                {
                    _pending = null;
                    _workerRunning = false;
                    _idle?.TrySetResult();
                    _idle = null;
                    return;
                }
                observation = _pending;
                _pending = null;
            }
            try { await ApplyObservationAsync(observation).ConfigureAwait(false); }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
            catch (Exception exception)
            {
                _persistencePending = true;
                Volatile.Write(ref _lastSynchronizationError, "Local AI review preference could not be saved; the latest observed runtime preference remains in memory.");
                _logger?.LogWarning(exception, "Local optional AI preference persistence failed; a subsequent fresh observation may retry.");
            }
        }
    }

    private async Task ApplyObservationAsync(Observation observation)
    {
        lock (_gate)
        {
            DateTime now = DateTime.UtcNow;
            if (_disposed || observation.Sequence != _latestSequence || !_ipc.IsConnected || observation.Enabled is not bool enabled ||
                observation.ProtocolVersion != 1 || observation.CapturedAtUtc == default || now < observation.CapturedAtUtc ||
                now - observation.CapturedAtUtc > TimeSpan.FromSeconds(15)) return;
            if (_settings.Current.IsUltronAiEnabled != enabled)
            {
                _settings.Current.IsUltronAiEnabled = enabled;
                DetectionPolicyRevision.Invalidate();
                _persistencePending = true;
            }
            // SettingsViewModel may have mirrored the same event first; equal runtime values do not prove disk persistence.
            if (_lastPersistedEnabled != enabled) _persistencePending = true;
            if (!_persistencePending) return;
        }
        await _settings.SaveAsync(_lifetime.Token).ConfigureAwait(false);
        _lastPersistedEnabled = observation.Enabled!.Value;
        _persistencePending = false;
        Volatile.Write(ref _lastSynchronizationError, null);
    }

    /// <summary>Unsubscribes and cancels queued persistence without blocking the UI; the existing worker observes cancellation and failures.</summary>
    public void Dispose()
    {
        Task worker;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _pending = null;
            worker = _worker;
        }
        _ipc.StatusChanged -= ObserveStatus;
        _lifetime.Cancel();
        _ = worker.ContinueWith(_ => _lifetime.Dispose(), CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    /// <summary>Unsubscribes and awaits any in-flight persistence, allowing isolated fixtures to remove their files safely.</summary>
    public async ValueTask DisposeAsync()
    {
        Dispose();
        Task worker;
        lock (_gate) worker = _worker;
        await worker.ConfigureAwait(false);
    }
}
