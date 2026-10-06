using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using AegisPC.Service.Scheduler;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AegisPC.Tests;

public sealed class ScheduledScanRegressionTests
{
    private readonly SettingsService _settings = new();
    private readonly RecordingResources _resources = new();
    private readonly ControlledScanner _scanner;
    private readonly ScanCoordinatorService _coordinator;
    private readonly ScanScheduler _scheduler;
    private readonly DateTime _now = new(2026, 9, 26, 12, 0, 0);

    public ScheduledScanRegressionTests()
    {
        _settings.Current.ScanScheduleEnabled = true;
        _scanner = new ControlledScanner(_resources);
        _coordinator = new ScanCoordinatorService(_scanner, new SecurityFindingService());
        _scheduler = new ScanScheduler(NullLogger<ScanScheduler>.Instance, _coordinator, _settings,
            new BatteryEnvironment(), _resources);
    }

    [Fact]
    public async Task HalfHourlySchedule_UsesThirtyMinutesRatherThanScheduledDailyHour()
    {
        _settings.Current.ScheduledScanIntervalHours = 0;
        _settings.Current.ScheduledScanHour = 19;

        Assert.True(await _scheduler.TryRunDueScanAsync(_now));
        Assert.False(await _scheduler.TryRunDueScanAsync(_now.AddMinutes(29)));
        Assert.True(await _scheduler.TryRunDueScanAsync(_now.AddMinutes(30)));
        Assert.Equal(2, _scanner.Calls);
    }

    [Theory]
    [InlineData(ScanStatus.Cancelled)]
    [InlineData(ScanStatus.Failed)]
    public async Task IncompleteScan_DoesNotConsumeDailySchedule(ScanStatus status)
    {
        _scanner.NextStatus = status;

        Assert.False(await _scheduler.TryRunDueScanAsync(_now));
        _scanner.NextStatus = ScanStatus.Completed;
        Assert.True(await _scheduler.TryRunDueScanAsync(_now.AddMinutes(1)));
        Assert.False(await _scheduler.TryRunDueScanAsync(_now.AddMinutes(2)));
        Assert.Equal(2, _scanner.Calls);
    }

    [Fact]
    public async Task ManualScan_IsNotClaimedAsScheduledWork()
    {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _scanner.BeforeReturn = () => release.Task;
        var manual = _coordinator.StartScanAsync(ScanType.Custom, "test-only");
        try
        {
            Assert.True(_coordinator.IsScanning);
            Assert.False(await _scheduler.TryRunDueScanAsync(_now));
        }
        finally { release.TrySetResult(true); }
        await manual;

        _scanner.BeforeReturn = null;
        Assert.True(await _scheduler.TryRunDueScanAsync(_now.AddMinutes(1)));
        Assert.Equal(2, _scanner.Calls);
    }

    [Fact]
    public async Task DisabledSchedule_DoesNotStartScan()
    {
        _settings.Current.ScanScheduleEnabled = false;

        Assert.False(await _scheduler.TryRunDueScanAsync(_now));
        Assert.Equal(0, _scanner.Calls);
    }

    [Fact]
    public async Task BatteryProfile_IsActuallyAppliedAndPreviousModeRestored()
    {
        _resources.SetMode(ScanResourceMode.Maximum);
        _settings.Current.ScanResourceMode = ScanResourceMode.Maximum;

        Assert.True(await _scheduler.TryRunDueScanAsync(_now));

        Assert.Equal(ScanResourceMode.Low, _scanner.ModeDuringScan);
        Assert.Equal(ScanResourceMode.Maximum, _resources.CurrentMode);
    }

    [Fact]
    public async Task BatteryProfile_DoesNotIncreaseAnAlreadyVeryLowResourcePreference()
    {
        _settings.Current.ScanResourceMode = ScanResourceMode.VeryLow;

        Assert.True(await _scheduler.TryRunDueScanAsync(_now));

        Assert.Equal(ScanResourceMode.VeryLow, _scanner.ModeDuringScan);
    }

    [Fact]
    public async Task ModeChangedDuringScheduledScan_IsNotOverwrittenAfterCompletion()
    {
        _resources.SetMode(ScanResourceMode.Maximum);
        _scanner.BeforeReturn = () => { _resources.SetMode(ScanResourceMode.High); return Task.CompletedTask; };

        Assert.True(await _scheduler.TryRunDueScanAsync(_now));

        Assert.Equal(ScanResourceMode.High, _resources.CurrentMode);
    }

    [Fact]
    public void ScheduledNotifications_IgnoreIncompleteScansAndDeduplicateCompletedFindings()
    {
        var background = new BackgroundProtectionService(null!, null!, _coordinator, settingsService: _settings);
        var result = new ScanResult
        {
            Status = ScanStatus.Failed,
            Findings = new() { new SecurityFinding { ObjectPath = "regression-" + Guid.NewGuid().ToString("N") + ".bin", RiskLevel = RiskLevel.Suspicious } }
        };
        int notifications = 0;
        background.OnNotificationRaised += (_, _) => notifications++;

        background.NotifyScheduledScanCompleted(result);
        Assert.Equal(0, notifications);
        result.Status = ScanStatus.Completed;
        background.NotifyScheduledScanCompleted(result);
        background.NotifyScheduledScanCompleted(result);
        Assert.Equal(1, notifications);
    }

    private sealed class BatteryEnvironment : IScanSchedulerEnvironmentProvider
    {
        public bool IsRunningOnBattery() => true;
        public bool IsFullscreenOrGameActive() => false;
        public double GetDiskActivityPercentage() => 0;
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

    private sealed class ControlledScanner(RecordingResources resources) : IFileScanner
    {
        public int Calls { get; private set; }
        public ScanStatus NextStatus { get; set; } = ScanStatus.Completed;
        public ScanResourceMode ModeDuringScan { get; private set; }
        public Func<Task>? BeforeReturn { get; set; }
        public bool IsPaused => false;
        public async Task<ScanResult> ScanDirectoryAsync(string path, ScanType scanType,
            IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
        {
            Calls++;
            ModeDuringScan = resources.CurrentMode;
            if (BeforeReturn != null) await BeforeReturn();
            return new ScanResult { Status = NextStatus, ScanType = scanType, ScannedFiles = 1, TotalFiles = 1 };
        }
        public Task<SecurityFinding?> ScanFileAsync(string filePath, CancellationToken cancellationToken = default) => Task.FromResult<SecurityFinding?>(null);
        public Task<FileScanDetailedResult> ScanFileDetailedAsync(string path, TimeSpan perFileTimeout, CancellationToken cancellationToken = default) =>
            Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero));
        public void PauseScan() { }
        public void ResumeScan() { }
    }
}
