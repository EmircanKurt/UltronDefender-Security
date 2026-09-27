using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.App.ViewModels;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Infrastructure.Database;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using AegisPC.Service.Scheduler;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AegisPC.Tests;

public sealed class ExclusionScheduleWorkflowTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "ExclusionScheduleReview-" + Guid.NewGuid().ToString("N"));

    public ExclusionScheduleWorkflowTests() => Directory.CreateDirectory(_directory);

    private async Task<DatabaseService> CreateDatabaseAsync()
    {
        var database = new DatabaseService(Path.Combine(_directory, "review.db"));
        await database.InitializeAsync();
        return database;
    }

    [Fact]
    public async Task OtherProcessSnapshot_RefreshesPersistedAddAndRemove()
    {
        var database = await CreateDatabaseAsync();
        var writer = new ExclusionService(database);
        var reader = new ExclusionService(database);
        await writer.InitializeAsync();
        await reader.InitializeAsync();
        var path = Path.Combine(_directory, "selected.txt");
        await File.WriteAllTextAsync(path, "benign review content");
        var entry = await writer.AddPathExclusionAsync(path, false);
        var refresher = Assert.IsAssignableFrom<IExclusionRefreshService>(reader);
        await refresher.ReloadAsync();
        Assert.True(reader.IsExcluded(path.ToUpperInvariant()));
        Assert.True(await writer.RemoveExclusionAsync(entry.Id));
        await refresher.ReloadAsync();
        Assert.False(reader.IsExcluded(path));
    }

    [Fact]
    public async Task FailedRefresh_RetainsPriorCommittedSnapshot()
    {
        var database = await CreateDatabaseAsync();
        var service = new ExclusionService(database);
        var path = Path.Combine(_directory, "selected.txt");
        await service.AddPathExclusionAsync(path, false);
        using (var connection = database.GetConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "ALTER TABLE Exclusions RENAME TO ExclusionsUnavailable;";
            await command.ExecuteNonQueryAsync();
        }
        await Assert.ThrowsAsync<SqliteException>(() => service.ReloadAsync());
        Assert.True(service.IsExcluded(path));
    }

    [Fact]
    public async Task ContentExclusion_DoesNotApplyToReplacementAtSamePath()
    {
        var service = new ExclusionService(await CreateDatabaseAsync());
        var path = Path.Combine(_directory, "selected.txt");
        await File.WriteAllTextAsync(path, "benign original content");
        var originalHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path)));
        await service.AddSha256ExclusionAsync(originalHash);
        Assert.True(service.IsExcluded(path, originalHash));
        await File.WriteAllTextAsync(path, "benign changed content");
        var changedHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path)));
        Assert.False(service.IsExcluded(path, changedHash));
        Assert.False(service.IsExcluded(path));
    }

    [Fact]
    public async Task DuplicatePersistedPath_RemovingOneKeepsOtherActiveEntry()
    {
        var database = await CreateDatabaseAsync();
        var service = new ExclusionService(database);
        var path = Path.Combine(_directory, "selected.txt");
        var first = await service.AddPathExclusionAsync(path, false);
        var second = await service.AddPathExclusionAsync(path.ToUpperInvariant(), false);
        Assert.True(await service.RemoveExclusionAsync(first.Id));
        Assert.True(service.IsExcluded(path));
        Assert.True(await service.RemoveExclusionAsync(second.Id));
        Assert.False(service.IsExcluded(path));
    }

    [Fact]
    public async Task InvalidNonHexHash_IsRejectedBeforePersistence()
    {
        var service = new ExclusionService(await CreateDatabaseAsync());
        await Assert.ThrowsAsync<ArgumentException>(() => service.AddSha256ExclusionAsync(new string('Z', 64)));
        Assert.Empty(await service.GetAllExclusionsAsync());
    }

    [Fact]
    public async Task ReturnedEntryMutation_DoesNotLeaveUndeletableExclusion()
    {
        var service = new ExclusionService(await CreateDatabaseAsync());
        var selected = Path.Combine(_directory, "selected.txt");
        var entry = await service.AddPathExclusionAsync(selected, false);
        entry.Value = Path.Combine(_directory, "unrelated.txt");
        Assert.True(await service.RemoveExclusionAsync(entry.Id));
        Assert.False(service.IsExcluded(selected));
    }

    [Fact]
    public async Task CancelledInitialization_PropagatesCancellation()
    {
        var service = new ExclusionService(await CreateDatabaseAsync());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.InitializeAsync(cancellation.Token));
    }

    [Fact]
    public async Task PersistedScheduleInterval_IsNotResetByStaleDisplayLabel()
    {
        var settings = new SettingsService(Path.Combine(_directory, "settings.json"));
        settings.Current.ScheduledScanIntervalHours = 1;
        settings.Current.ScheduledScanDay = "Her Gün";
        using var viewModel = new SettingsViewModel(settingsService: settings);
        await viewModel.SaveSettingsAsync();
        Assert.Equal(1, settings.Current.ScheduledScanIntervalHours);
        var reloaded = new SettingsService(Path.Combine(_directory, "settings.json"));
        await reloaded.LoadAsync();
        Assert.Equal(1, reloaded.Current.ScheduledScanIntervalHours);
    }

    [Theory]
    [InlineData(null, true, ScanResourceMode.Low)]
    [InlineData(false, true, ScanResourceMode.High)]
    [InlineData(true, false, ScanResourceMode.Auto)]
    public async Task TimedSchedule_DistinguishesUnknownDesktopFromObservedFullscreen(bool? fullscreen, bool shouldRun, ScanResourceMode expectedMode)
    {
        var settings = new SettingsService(Path.Combine(_directory, "settings.json"));
        settings.Current.ScanScheduleEnabled = true;
        settings.Current.ScanResourceMode = ScanResourceMode.High;
        var resources = new Resources();
        var scanner = new Scanner(resources);
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        using var scheduler = new ScanScheduler(NullLogger<ScanScheduler>.Instance, coordinator, settings,
            new DesktopEnvironment(fullscreen), resources);
        Assert.Equal(shouldRun, await scheduler.TryRunDueScanAsync(new DateTime(2026, 9, 27, 13, 0, 0)));
        Assert.Equal(expectedMode, scanner.ModeDuringScan);
    }

    [Fact]
    public async Task IdleScan_StillDefersUnobservableDesktop()
    {
        var settings = new SettingsService(Path.Combine(_directory, "settings.json"));
        var resources = new Resources();
        var scanner = new Scanner(resources);
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        using var scheduler = new ScanScheduler(NullLogger<ScanScheduler>.Instance, coordinator, settings,
            new DesktopEnvironment(null), resources, idleTimeProvider: new Idle());
        Assert.False(await scheduler.TryRunIdleScanAsync(DateTime.UtcNow));
        Assert.Equal(0, scanner.Calls);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, true);
    }

    private sealed class DesktopEnvironment(bool? fullscreen) : IScanSchedulerEnvironmentProvider, IScanSchedulerDesktopStatusProvider
    {
        public bool? GetFullscreenOrGameActivity() => fullscreen;
        public bool IsFullscreenOrGameActive() => fullscreen != false;
        public bool IsRunningOnBattery() => false;
        public double GetDiskActivityPercentage() => 0;
    }

    private sealed class Idle : IIdleTimeProvider
    {
        public TimeSpan? GetIdleDuration() => TimeSpan.FromMinutes(30);
    }

    private sealed class Resources : IScanResourceManager
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

    private sealed class Scanner(Resources resources) : IFileScanner
    {
        public int Calls { get; private set; }
        public ScanResourceMode ModeDuringScan { get; private set; } = ScanResourceMode.Auto;
        public bool IsPaused => false;
        public Task<ScanResult> ScanDirectoryAsync(string path, ScanType scanType, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
        {
            Calls++;
            ModeDuringScan = resources.CurrentMode;
            return Task.FromResult(new ScanResult { Status = ScanStatus.Completed, ScanType = scanType });
        }
        public Task<SecurityFinding?> ScanFileAsync(string filePath, CancellationToken cancellationToken = default) => Task.FromResult<SecurityFinding?>(null);
        public Task<FileScanDetailedResult> ScanFileDetailedAsync(string path, TimeSpan perFileTimeout, CancellationToken cancellationToken = default) =>
            Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero));
        public void PauseScan() { }
        public void ResumeScan() { }
    }
}
