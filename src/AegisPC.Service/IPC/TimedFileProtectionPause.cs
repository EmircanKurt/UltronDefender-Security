using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.IPC;

/// <summary>Serializes manual/timed file controls; persists recovery before stopping and never modifies other shields.</summary>
public sealed class TimedFileProtectionPause(
    Func<ProtectionPauseState?> readState, Func<ProtectionPauseState?, Task> saveState,
    Func<bool, Task> applyEnabled, Func<bool> isEnabled, TimeProvider? clock = null)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private bool _restartRecoveryRequested;

    /// <summary>Accepts ten minutes, one/five hours or next service start; nested requests cannot silently extend an existing pause.</summary>
    public async Task PauseAsync(int minutes, bool resumeOnServiceStart)
    {
        if (resumeOnServiceStart ? minutes != 0 : minutes is not (10 or 60 or 300))
            throw new ArgumentOutOfRangeException(nameof(minutes), "Unsupported pause duration.");
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (readState() != null || !isEnabled()) throw new InvalidOperationException("File protection is paused or not active.");
            var intent = new ProtectionPauseState
            {
                ResumeAtUtc = resumeOnServiceStart ? null : _clock.GetUtcNow().UtcDateTime.AddMinutes(minutes),
                ResumeOnServiceStart = resumeOnServiceStart,
                RestoreImmediately = true
            };
            await saveState(intent).ConfigureAwait(false);
            try
            {
                await applyEnabled(false).ConfigureAwait(false);
                await saveState(intent with { RestoreImmediately = false }).ConfigureAwait(false);
            }
            catch (Exception stopFailure)
            {
                try
                {
                    await applyEnabled(true).ConfigureAwait(false);
                    await saveState(null).ConfigureAwait(false);
                }
                catch (Exception restoreFailure) { throw new AggregateException("Pause failed; durable restoration remains pending.", stopFailure, restoreFailure); }
                throw;
            }
        }
        finally { _gate.Release(); }
    }

    /// <summary>Clears recovery intent only after an explicit manual transition succeeds; shares the pause/recovery lock.</summary>
    public async Task SetManualEnabledAsync(bool enabled)
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            await applyEnabled(enabled).ConfigureAwait(false);
            await saveState(null).ConfigureAwait(false);
            _restartRecoveryRequested = false;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Restores due/startup pauses; failed restoration preserves intent and startup retries across the running service.</summary>
    public async Task<bool> RecoverDueAsync(bool serviceStarting = false)
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var state = readState();
            if (state == null) return false;
            if (serviceStarting && state.ResumeOnServiceStart) _restartRecoveryRequested = true;
            var now = _clock.GetUtcNow().UtcDateTime;
            bool invalid = state.ResumeOnServiceStart ? state.ResumeAtUtc.HasValue
                : state.ResumeAtUtc is not DateTime deadline || deadline.Kind != DateTimeKind.Utc || deadline > now.AddHours(5);
            if (!_restartRecoveryRequested && !state.RestoreImmediately && !invalid && !(state.ResumeAtUtc <= now)) return false;
            await applyEnabled(true).ConfigureAwait(false);
            await saveState(null).ConfigureAwait(false);
            _restartRecoveryRequested = false;
            return true;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Owned by service cancellation, not the tray; retries logged failures with thirty-second backoff.</summary>
    public async Task RunRecoveryAsync(ILogger logger, CancellationToken cancellationToken)
    {
        bool starting = true;
        while (!cancellationToken.IsCancellationRequested)
        {
            var delay = TimeSpan.FromSeconds(5);
            try { await RecoverDueAsync(starting).ConfigureAwait(false); starting = false; }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Timed file-shield restoration failed; recovery remains pending.");
                delay = TimeSpan.FromSeconds(30);
            }
            try { await Task.Delay(delay, cancellationToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return; }
        }
    }
}
