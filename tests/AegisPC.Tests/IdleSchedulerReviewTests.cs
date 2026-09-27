using System.IO;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Infrastructure.Platform;
using AegisPC.Security.Scanning;
using AegisPC.Service.Scheduler;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Exercises safe background ownership and temp-file persistence, not physical AFK or laptop battery behavior.</summary>
public sealed class IdleSchedulerReviewTests : IDisposable
{
    private readonly string _temporaryDirectory = Path.Combine(Path.GetTempPath(), "AegisIdleReview_" + Guid.NewGuid().ToString("N"));
    private readonly SettingsService _settings;
    private readonly IdleSample _idle = new();
    private readonly EnvironmentSample _environment = new();
    private readonly ControlledScanner _scanner = new();
    private readonly ScanCoordinatorService _coordinator;
    private readonly FileScanScheduleStateStore _state;
    private readonly DateTime _now = new(2026, 9, 26, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>Creates isolated files and fake environment samples; no installed settings or security state are touched.</summary>
    public IdleSchedulerReviewTests()
    {
        Directory.CreateDirectory(_temporaryDirectory);
        _settings = new SettingsService(Path.Combine(_temporaryDirectory, "settings.json"));
        _settings.Current.IdleScanEnabled = true;
        _settings.Current.IdleScanThresholdMinutes = 10;
        _settings.Current.IdleScanIntervalHours = 24;
        _state = new FileScanScheduleStateStore(Path.Combine(_temporaryDirectory, "schedule.json"));
        _coordinator = new ScanCoordinatorService(_scanner, new SecurityFindingService());
    }

    private ScanScheduler CreateScheduler() => new(NullLogger<ScanScheduler>.Instance,
        _coordinator, _settings, _environment, idleTimeProvider: _idle, stateStore: _state,
        monitorInterval: TimeSpan.FromMilliseconds(10));

    [Theory]
    [InlineData("disabled")]
    [InlineData("active")]
    [InlineData("unknownIdle")]
    [InlineData("battery")]
    [InlineData("fullscreen")]
    [InlineData("diskBusy")]
    [InlineData("unknownDisk")]
    public async Task UnsafeOrOptedOutIdleWork_IsDeferred(string condition)
    {
        switch (condition)
        {
            case "disabled": _settings.Current.IdleScanEnabled = false; break;
            case "active": _idle.Duration = TimeSpan.FromMinutes(9); break;
            case "unknownIdle": _idle.Duration = null; break;
            case "battery": _environment.Battery = true; break;
            case "fullscreen": _environment.Fullscreen = true; break;
            case "diskBusy": _environment.DiskBusy = 80; break;
            case "unknownDisk": _environment.DiskBusy = double.NaN; break;
        }
        using var scheduler = CreateScheduler();
        Assert.False(await scheduler.TryRunIdleScanAsync(_now));
        Assert.Equal(0, _scanner.Calls);
        Assert.Null(_state.Load().IdleScanCompletedUtc);
    }

    [Fact]
    public async Task CompletedIdleScan_SurvivesRestartAndDoesNotRepeatBeforeItsInterval()
    {
        using (var scheduler = CreateScheduler()) Assert.True(await scheduler.TryRunIdleScanAsync(_now));
        Assert.Equal(_now, _state.Load().IdleScanCompletedUtc);
        using var restarted = CreateScheduler();
        Assert.False(await restarted.TryRunIdleScanAsync(_now.AddHours(23)));
        Assert.True(await restarted.TryRunIdleScanAsync(_now.AddHours(24)));
        Assert.Equal(2, _scanner.Calls);
    }

    [Theory]
    [InlineData(ScanStatus.Cancelled)]
    [InlineData(ScanStatus.Failed)]
    public async Task IncompleteIdleScan_DoesNotConsumeTheCompletionInterval(ScanStatus status)
    {
        _scanner.Status = status;
        using var scheduler = CreateScheduler();
        Assert.False(await scheduler.TryRunIdleScanAsync(_now));
        Assert.Null(_state.Load().IdleScanCompletedUtc);
        _scanner.Status = ScanStatus.Completed;
        Assert.True(await scheduler.TryRunIdleScanAsync(_now.AddMinutes(1)));
    }

    [Fact]
    public async Task UserReturns_OnlyTheOwnedIdleScanIsCancelledAndRemainsDue()
    {
        _scanner.WaitForCancellation = true;
        using var scheduler = CreateScheduler();
        var running = scheduler.TryRunIdleScanAsync(_now);
        await _scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        _idle.Duration = TimeSpan.Zero;
        Assert.False(await running.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.True(_scanner.CancellationObserved);
        Assert.Null(_state.Load().IdleScanCompletedUtc);
        _idle.Duration = TimeSpan.FromMinutes(20);
        _scanner.WaitForCancellation = false;
        Assert.True(await scheduler.TryRunIdleScanAsync(_now.AddMinutes(1)));
    }

    [Fact]
    public async Task ShutdownToken_CancelsAnOwnedScanWithoutMarkingItCompleted()
    {
        _scanner.WaitForCancellation = true;
        using var cancellation = new CancellationTokenSource();
        using var scheduler = CreateScheduler();
        var running = scheduler.TryRunIdleScanAsync(_now, cancellation.Token);
        await _scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();
        Assert.False(await running.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.True(_scanner.CancellationObserved);
        Assert.Null(_state.Load().IdleScanCompletedUtc);
    }

    [Fact]
    public async Task ExistingManualScan_IsNeitherClaimedNorCancelledByIdleScheduler()
    {
        _scanner.WaitForCancellation = true;
        var manual = _coordinator.StartScanAsync(ScanType.Custom, "test-only");
        await _scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        using var scheduler = CreateScheduler();
        try
        {
            Assert.False(await scheduler.TryRunIdleScanAsync(_now));
            Assert.False(_scanner.CancellationObserved);
            Assert.Equal(1, _scanner.Calls);
        }
        finally { _coordinator.CancelScan(); }
        await manual.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task DailySchedule_MissedHourIsCaughtUpAndCompletionSurvivesRestart()
    {
        _settings.Current.ScanScheduleEnabled = true;
        _settings.Current.ScheduledScanHour = 6;
        _settings.Current.ScheduledScanIntervalHours = 24;
        using (var scheduler = CreateScheduler()) Assert.True(await scheduler.TryRunDueScanAsync(_now.ToLocalTime()));
        using var restarted = CreateScheduler();
        Assert.False(await restarted.TryRunDueScanAsync(_now.AddHours(1).ToLocalTime()));
        Assert.False(await restarted.TryRunIdleScanAsync(_now.AddHours(1)));
        Assert.Equal(1, _scanner.Calls);
    }

    [Fact]
    public async Task FutureFormatState_IsNotOverwrittenAndDefersAutomaticWork()
    {
        string path = Path.Combine(_temporaryDirectory, "schedule.json");
        const string futureSnapshot = "{\"Version\":999}";
        await File.WriteAllTextAsync(path, futureSnapshot);
        using var scheduler = CreateScheduler();
        Assert.False(await scheduler.TryRunIdleScanAsync(_now));
        Assert.Equal(futureSnapshot, await File.ReadAllTextAsync(path));
        Assert.Equal(0, _scanner.Calls);
    }

    [Fact]
    public async Task StateStore_UsesCommittedBackupWhenLatestJsonIsCorrupt()
    {
        await _state.SaveAsync(new ScanScheduleState { IdleScanCompletedUtc = _now });
        await _state.SaveAsync(new ScanScheduleState { IdleScanCompletedUtc = _now.AddHours(24) });
        await File.WriteAllTextAsync(Path.Combine(_temporaryDirectory, "schedule.json"), "not-json");
        Assert.Equal(_now, _state.Load().IdleScanCompletedUtc);
        Assert.Empty(Directory.EnumerateFiles(_temporaryDirectory, "*.tmp"));
    }

    [Fact]
    public async Task UserSelectsTheTemporaryBatteryMode_TheirPersistedPreferenceIsNotOverwritten()
    {
        var resources = new RecordingResources();
        resources.SetMode(ScanResourceMode.Maximum);
        _environment.Battery = true;
        _settings.Current.SkipIdleScanOnBattery = false;
        _settings.Current.ScanResourceMode = ScanResourceMode.Maximum;
        _scanner.BeforeReturn = () =>
        {
            _settings.Current.ScanResourceMode = ScanResourceMode.Low;
            resources.SetMode(ScanResourceMode.Low);
        };
        using var scheduler = new ScanScheduler(NullLogger<ScanScheduler>.Instance,
            _coordinator, _settings, _environment, resources, idleTimeProvider: _idle, stateStore: _state);
        Assert.True(await scheduler.TryRunIdleScanAsync(_now));
        Assert.Equal(ScanResourceMode.Low, resources.CurrentMode);
    }

    [Theory]
    [InlineData(false, 100, 100)]
    [InlineData(true, 90, 10)]
    [InlineData(true, 0, 100)]
    [InlineData(true, 100, 0)]
    [InlineData(true, -1, 100)]
    [InlineData(true, 101, 100)]
    public void DiskTelemetry_InvalidSamplesNeverMasqueradeAsIdle(bool available, double idle, double expectedBusy)
    {
        Assert.Equal(expectedBusy, WindowsScanSchedulerEnvironmentProvider.NormalizeDiskActivity(available, idle));
    }

    /// <summary>Removes only this test's uniquely created temporary folder.</summary>
    public void Dispose() => Directory.Delete(_temporaryDirectory, recursive: true);

    private sealed class IdleSample : IIdleTimeProvider
    {
        public TimeSpan? Duration { get; set; } = TimeSpan.FromMinutes(20);
        public TimeSpan? GetIdleDuration() => Duration;
    }

    private sealed class EnvironmentSample : IScanSchedulerEnvironmentProvider
    {
        public bool Battery { get; set; }
        public bool Fullscreen { get; set; }
        public double DiskBusy { get; set; }
        public bool IsRunningOnBattery() => Battery;
        public bool IsFullscreenOrGameActive() => Fullscreen;
        public double GetDiskActivityPercentage() => DiskBusy;
    }

    private sealed class ControlledScanner : IFileScanner
    {
        public int Calls { get; private set; }
        public bool WaitForCancellation { get; set; }
        public bool CancellationObserved { get; private set; }
        public ScanStatus Status { get; set; } = ScanStatus.Completed;
        public Action? BeforeReturn { get; set; }
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool IsPaused => false;
        public async Task<ScanResult> ScanDirectoryAsync(string path, ScanType scanType,
            IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
        {
            Calls++;
            Started.TrySetResult();
            if (WaitForCancellation)
            {
                try { await Task.Delay(Timeout.Infinite, cancellationToken); }
                catch (OperationCanceledException) { CancellationObserved = true; return new ScanResult { Status = ScanStatus.Cancelled }; }
            }
            BeforeReturn?.Invoke();
            return new ScanResult { Status = Status, ScanType = scanType, ScannedFiles = 1, TotalFiles = 1 };
        }
        public Task<SecurityFinding?> ScanFileAsync(string filePath, CancellationToken cancellationToken = default) => Task.FromResult<SecurityFinding?>(null);
        public Task<FileScanDetailedResult> ScanFileDetailedAsync(string path, TimeSpan perFileTimeout, CancellationToken cancellationToken = default) =>
            Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero));
        public void PauseScan() { }
        public void ResumeScan() { }
    }

    private sealed class RecordingResources : IScanResourceManager
    {
        public ScanResourceMode CurrentMode { get; private set; } = ScanResourceMode.Auto;
        public ScanResourceProfile ActiveProfile => ScanResourceProfile.Create(CurrentMode, false, 4, 8L * 1024 * 1024 * 1024);
        public event Action<ScanResourceProfile>? ProfileChanged { add { } remove { } }
        public void SetMode(ScanResourceMode mode) => CurrentMode = mode;
        public Task EnterWorkerSlotAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public void ExitWorkerSlot() { }
        public Task ApplyPacingAsync(int processedFileCounter, CancellationToken cancellationToken) => Task.CompletedTask;
        public void RefreshProfile() { }
    }
}
