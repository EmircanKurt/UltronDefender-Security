using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.RealTime;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Scheduler
{
    /// <summary>Runs opt-in scheduled and idle scans while yielding to user activity and preserving completion state.</summary>
    public class ScanScheduler : BackgroundService
    {
        private readonly ILogger<ScanScheduler> _logger;
        private readonly IScanCoordinatorService _scanCoordinator;
        private readonly SettingsService _settingsService;
        private readonly IScanSchedulerEnvironmentProvider? _envProvider;
        private readonly IScanResourceManager? _resourceManager;
        private readonly IBackgroundProtectionService? _backgroundProtection;
        private readonly IIdleTimeProvider? _idleTimeProvider;
        private readonly IScanScheduleStateStore? _stateStore;
        private readonly TimeSpan _monitorInterval;
        private readonly ScanScheduleState _state;
        private readonly bool _stateAvailable = true;
        private readonly SemaphoreSlim _scheduleGate = new(1, 1);

        /// <summary>
        /// Creates the scheduler with optional read-only idle and persistence providers.
        /// Background work requires the coordinator's ownership-safe background-start interface.
        /// </summary>
        public ScanScheduler(
            ILogger<ScanScheduler> logger,
            IScanCoordinatorService scanCoordinator,
            SettingsService settingsService,
            IScanSchedulerEnvironmentProvider? envProvider = null,
            IScanResourceManager? resourceManager = null,
            IBackgroundProtectionService? backgroundProtection = null,
            IIdleTimeProvider? idleTimeProvider = null,
            IScanScheduleStateStore? stateStore = null,
            TimeSpan? monitorInterval = null)
        {
            _logger = logger;
            _scanCoordinator = scanCoordinator;
            _settingsService = settingsService;
            _envProvider = envProvider;
            _resourceManager = resourceManager;
            _backgroundProtection = backgroundProtection;
            _idleTimeProvider = idleTimeProvider;
            _stateStore = stateStore;
            _monitorInterval = monitorInterval ?? TimeSpan.FromSeconds(2);
            if (_monitorInterval <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(monitorInterval));
            try { _state = _stateStore?.Load() ?? new ScanScheduleState(); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
            {
                _logger.LogWarning(ex, "Scheduler state is unavailable; automatic scans are deferred until state can be recovered.");
                _state = new ScanScheduleState();
                _stateAvailable = false;
            }
        }

        /// <summary>Attempts a due quick scan; busy or disruptive environments defer it without consuming its schedule.</summary>
        public async Task<bool> TryRunDueScanAsync(DateTime now, CancellationToken cancellationToken = default)
        {
            if (!_stateAvailable || !await _scheduleGate.WaitAsync(0, cancellationToken)) return false;
            try
            {
                var settings = _settingsService.Current;
                if (!settings.ScanScheduleEnabled || _scanCoordinator.IsScanning) return false;
                DateTime? lastRunDate = _state.ScheduledScanCompletedUtc?.ToLocalTime();
                if (lastRunDate.HasValue && now < lastRunDate.Value) return false;
                bool isDue = settings.ScheduledScanIntervalHours < 24
                    ? ScanScheduleEvaluator.IsIntervalScanDue(now,
                        settings.ScheduledScanIntervalHours == 0 ? 0.5 : settings.ScheduledScanIntervalHours, lastRunDate)
                    : now.Hour >= settings.ScheduledScanHour && lastRunDate?.Date != now.Date;
                return isDue && await RunOwnedScanAsync(now, idleScan: false, cancellationToken);
            }
            finally { _scheduleGate.Release(); }
        }

        /// <summary>Attempts a quick scan only after measured idleness and the configured completion interval.</summary>
        public async Task<bool> TryRunIdleScanAsync(DateTime nowUtc, CancellationToken cancellationToken = default)
        {
            if (!_stateAvailable || !await _scheduleGate.WaitAsync(0, cancellationToken)) return false;
            try
            {
                if (!_settingsService.Current.IdleScanEnabled || _scanCoordinator.IsScanning) return false;
                DateTime utc = NormalizeUtc(nowUtc);
                DateTime? mostRecent = MostRecentCompletion();
                TimeSpan interval = TimeSpan.FromHours(Math.Clamp(_settingsService.Current.IdleScanIntervalHours, 1, 168));
                if (mostRecent.HasValue && utc - mostRecent.Value < interval) return false;
                return await RunOwnedScanAsync(utc, idleScan: true, cancellationToken);
            }
            finally { _scheduleGate.Release(); }
        }

        private DateTime? MostRecentCompletion() =>
            _state.ScheduledScanCompletedUtc is DateTime scheduled && _state.IdleScanCompletedUtc is DateTime idle
                ? (scheduled > idle ? scheduled : idle)
                : _state.ScheduledScanCompletedUtc ?? _state.IdleScanCompletedUtc;

        private bool EnvironmentAllowsScan(bool idleScan)
        {
            if (_envProvider == null) return false;
            bool? fullscreen = DesktopActivity();
            if (fullscreen == true || (idleScan && fullscreen == null)) return false;
            double diskBusy = _envProvider?.GetDiskActivityPercentage() ?? 0;
            if (!double.IsFinite(diskBusy) || ScanScheduleEvaluator.ShouldThrottleForDiskBusy(diskBusy)) return false;
            if (!idleScan) return _settingsService.Current.ScanScheduleEnabled;
            var settings = _settingsService.Current;
            if (!settings.IdleScanEnabled || _idleTimeProvider == null) return false;
            if (settings.SkipIdleScanOnBattery && _envProvider?.IsRunningOnBattery() == true) return false;
            TimeSpan? duration = _idleTimeProvider.GetIdleDuration();
            return duration.HasValue && duration.Value >= TimeSpan.FromMinutes(Math.Clamp(settings.IdleScanThresholdMinutes, 1, 240));
        }

        private bool? DesktopActivity() => _envProvider is IScanSchedulerDesktopStatusProvider desktop
            ? desktop.GetFullscreenOrGameActivity() : _envProvider?.IsFullscreenOrGameActive();

        private async Task<bool> RunOwnedScanAsync(DateTime now, bool idleScan, CancellationToken cancellationToken)
        {
            if (_scanCoordinator is not IBackgroundScanCoordinator backgroundCoordinator || !EnvironmentAllowsScan(idleScan)) return false;
            ScanResourceMode? previousMode = null;
            bool profileApplied = false;
            ScanResourceMode preferredMode = _settingsService.Current.ScanResourceMode;
            ScanResourceMode selected = ScanScheduleEvaluator.DetermineScheduledScanProfile(
                _envProvider?.IsRunningOnBattery() == true || DesktopActivity() == null, preferredMode);
            long started = Stopwatch.GetTimestamp();
            using var ownedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            try
            {
                var scan = backgroundCoordinator.TryStartBackgroundScanAsync(ScanType.Quick, ownedCancellation.Token, () =>
                {
                    previousMode = _resourceManager?.CurrentMode;
                    _resourceManager?.SetMode(selected);
                    profileApplied = true;
                });
                while (!scan.IsCompleted)
                {
                    var wakeup = Task.Delay(_monitorInterval, ownedCancellation.Token);
                    if (await Task.WhenAny(scan, wakeup) == scan) break;
                    if (ownedCancellation.IsCancellationRequested || !EnvironmentAllowsScan(idleScan))
                    {
                        _logger.LogInformation("Deferring owned {Kind} scan because shutdown, user activity, or system pressure resumed.",
                            idleScan ? "idle" : "scheduled");
                        ownedCancellation.Cancel();
                        break;
                    }
                }
                ScanResult? result = await scan;
                if (ownedCancellation.IsCancellationRequested || result?.Status != ScanStatus.Completed) return false;
                // Persist completion to second resolution so long scans postpone the next run from their end, not their start.
                DateTime completedUtc = NormalizeUtc(now).AddSeconds(Math.Floor(Stopwatch.GetElapsedTime(started).TotalSeconds));
                if (idleScan) _state.IdleScanCompletedUtc = completedUtc;
                else _state.ScheduledScanCompletedUtc = completedUtc;
                await PersistCompletionAsync();
                _logger.LogInformation("Owned {Kind} scan completed. Files: {Files}, Threats: {Threats}",
                    idleScan ? "idle" : "scheduled", result.ScannedFiles, result.Findings.Count);
                try { _backgroundProtection?.NotifyScheduledScanCompleted(result); }
                catch (Exception ex) { _logger.LogWarning(ex, "Completed scan notification failed; completion state remains committed."); }
                return true;
            }
            catch (OperationCanceledException) when (ownedCancellation.IsCancellationRequested) { return false; }
            finally
            {
                // Preserve a preference changed by the user while this owned background scan was running.
                if (profileApplied && previousMode.HasValue && _resourceManager?.CurrentMode == selected &&
                    _settingsService.Current.ScanResourceMode == preferredMode)
                    _resourceManager.SetMode(previousMode.Value);
            }
        }

        private async Task PersistCompletionAsync()
        {
            if (_stateStore == null) return;
            try { await _stateStore.SaveAsync(_state, CancellationToken.None); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
            {
                _logger.LogWarning(ex, "Scan completion could not be persisted; in-memory scheduling remains active.");
            }
        }

        private static DateTime NormalizeUtc(DateTime value) => value.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(value, DateTimeKind.Local).ToUniversalTime() : value.ToUniversalTime();

        /// <summary>Checks scheduled then idle work once per minute; cancelling the host cancels only work it owns.</summary>
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("ScanScheduler background worker started.");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // Check every minute
                    await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);

                    bool scheduled = await TryRunDueScanAsync(DateTime.Now, stoppingToken);
                    if (!scheduled && !stoppingToken.IsCancellationRequested)
                        await TryRunIdleScanAsync(DateTime.UtcNow, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error in ScanScheduler loop.");
                }
            }

            _logger.LogInformation("ScanScheduler background worker stopped.");
        }
    }
}
