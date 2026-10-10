using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Policy;
using AegisPC.Contracts.Safety;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.Policy;
using AegisPC.Security.Safety;
using AegisPC.App.ViewModels;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;
using Xunit;

namespace AegisPC.Tests;

public sealed class SettingsPersistenceRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisSettingsRegression_" + Guid.NewGuid().ToString("N"));
    private string SettingsPath => Path.Combine(_root, "settings.json");

    public SettingsPersistenceRegressionTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public async Task TruncatedSettings_UseDefaultsWithoutOverwritingDamagedFile()
    {
        const string damaged = "{\"IsFileProtectionEnabled\":";
        await File.WriteAllTextAsync(SettingsPath, damaged);
        var service = new SettingsService(SettingsPath);

        await service.LoadAsync();

        Assert.True(service.Current.IsFileProtectionEnabled);
        Assert.True(service.Current.IsRansomwareShieldEnabled);
        Assert.Equal(damaged, await File.ReadAllTextAsync(SettingsPath));
    }

    [Fact]
    public async Task CorruptPrimarySettings_RecoverPreviousSavedVersion()
    {
        var service = new SettingsService(SettingsPath);
        service.Current.NotificationsEnabled = false;
        await service.SaveAsync();
        service.Current.NotificationsEnabled = true;
        await service.SaveAsync();
        await File.WriteAllTextAsync(SettingsPath, "{broken-json");

        var reloaded = new SettingsService(SettingsPath);
        await reloaded.LoadAsync();

        Assert.False(reloaded.Current.NotificationsEnabled);
        Assert.Empty(Directory.GetFiles(_root, "*.tmp"));
    }

    [Fact]
    public async Task LoadedSettings_AreValidatedBeforeTheyReachServiceWorkers()
    {
        await File.WriteAllTextAsync(SettingsPath,
            "{\"PerformanceSampleIntervalMs\":-1,\"MaxScanConcurrency\":0,\"AutoQuarantineThreshold\":999," +
            "\"ScheduledScanHour\":30,\"ScanResourceMode\":999,\"DismissedIncidentIds\":null}");
        var service = new SettingsService(SettingsPath);

        await service.LoadAsync();

        Assert.Equal(500, service.Current.PerformanceSampleIntervalMs);
        Assert.DoesNotContain("MaxScanConcurrency", JsonSerializer.Serialize(service.Current));
        Assert.Equal(100, service.Current.AutoQuarantineThreshold);
        Assert.Equal(23, service.Current.ScheduledScanHour);
        Assert.Equal(ScanResourceMode.Auto, service.Current.ScanResourceMode);
        Assert.NotNull(service.Current.DismissedIncidentIds);
    }

    [Fact]
    public async Task FailedAtomicReplacement_KeepsLastSavedSettingsAndReleasesLock()
    {
        var service = new SettingsService(SettingsPath);
        await service.SaveAsync();
        var previous = await File.ReadAllTextAsync(SettingsPath);
        service.Current.NotificationsEnabled = false;
        using (var reader = new FileStream(SettingsPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            await Assert.ThrowsAnyAsync<IOException>(() => service.SaveAsync());

        Assert.Equal(previous, await File.ReadAllTextAsync(SettingsPath));
        Assert.Empty(Directory.GetFiles(_root, "*.tmp"));
        await service.SaveAsync();
        var reloaded = new SettingsService(SettingsPath);
        await reloaded.LoadAsync();
        Assert.False(reloaded.Current.NotificationsEnabled);
    }

    [Fact]
    public async Task CancelledSave_DoesNotTruncateExistingSettings()
    {
        var service = new SettingsService(SettingsPath);
        await service.SaveAsync();
        var previous = await File.ReadAllTextAsync(SettingsPath);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.SaveAsync(cancellation.Token));

        Assert.Equal(previous, await File.ReadAllTextAsync(SettingsPath));
    }
}

public sealed class TransactionalVaultRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisVaultRegression_" + Guid.NewGuid().ToString("N"));
    private readonly TransactionalQuarantineEngine _engine;
    private string Vault => Path.Combine(_root, "vault");

    public TransactionalVaultRegressionTests()
    {
        Directory.CreateDirectory(_root);
        _engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
    }

    public void Dispose()
    {
        _engine.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            try { Directory.Delete(_root, recursive: true); } catch { }
        }
    }

    private static QuarantineRequest Request(string path) => new() { TargetFilePath = path, ForceKillHoldingProcesses = false };

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(1024)]
    public async Task VaultRoundTrip_RestoresExactBytesAfterReload(int length)
    {
        var path = Path.Combine(_root, "sample.bin");
        var payload = Enumerable.Range(0, length).Select(i => (byte)(i % 251)).ToArray();
        await File.WriteAllBytesAsync(path, payload);
        var quarantined = await _engine.ExecuteQuarantineAsync(Request(path));

        Assert.True(quarantined.Success, quarantined.Message);
        Assert.False(File.Exists(path));
        using var reloaded = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var restored = await reloaded.ExecuteRestoreAsync(quarantined.QuarantineId);

        Assert.True(restored.Success, restored.Message);
        Assert.Equal(payload, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task LockedSource_FailsWithoutCommittingQuarantine()
    {
        var path = Path.Combine(_root, "locked.bin");
        await File.WriteAllTextAsync(path, "harmless locked regression payload");
        using var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);

        var result = await _engine.ExecuteQuarantineAsync(Request(path));

        Assert.False(result.Success);
        Assert.Equal(QuarantineTransactionStatus.RolledBack, result.Status);
        Assert.True(File.Exists(path));
        Assert.Empty(Directory.GetFiles(Vault, "*.quar"));
        Assert.Empty(await _engine.Database.GetAllEntriesAsync());
        var indexPath = Path.Combine(Vault, "quarantine_index.json");
        if (File.Exists(indexPath))
            Assert.Empty(JsonSerializer.Deserialize<QuarantineEntry[]>(await File.ReadAllTextAsync(indexPath))!);
    }

    [Fact]
    public async Task IndexPersistenceFailure_LeavesOriginalFileUntouched()
    {
        var path = Path.Combine(_root, "original.bin");
        const string payload = "original must survive a failed index write";
        await File.WriteAllTextAsync(path, payload);
        Directory.CreateDirectory(Path.Combine(Vault, "quarantine_index.json"));

        var result = await _engine.ExecuteQuarantineAsync(Request(path));

        Assert.False(result.Success);
        Assert.Equal(payload, await File.ReadAllTextAsync(path));
        Assert.Empty(Directory.GetFiles(Vault, "*.quar"));
        Assert.Empty(Directory.GetFiles(Vault, "*.tmp"));
    }

    [Fact]
    public async Task ConcurrentQuarantines_HaveUniqueRecoverableIds()
    {
        var paths = Enumerable.Range(0, 4).Select(i => Path.Combine(_root, $"concurrent-{i}.bin")).ToArray();
        foreach (var path in paths) await File.WriteAllBytesAsync(path, new byte[1024 * 1024]);

        var results = await Task.WhenAll(paths.Select(path => _engine.ExecuteQuarantineAsync(Request(path))));

        Assert.All(results, result => Assert.True(result.Success, result.Message));
        Assert.Equal(results.Length, results.Select(result => result.QuarantineId).Distinct().Count());
        using var reloaded = new TransactionalQuarantineEngine(customVaultDir: Vault);
        foreach (var result in results)
        {
            var restored = await reloaded.ExecuteRestoreAsync(result.QuarantineId);
            Assert.True(restored.Success, restored.Message);
            Assert.Equal(1024 * 1024, new FileInfo(result.OriginalPath).Length);
        }
    }

    [Fact]
    public async Task Restore_ProtectsAnExistingDestination()
    {
        var path = Path.Combine(_root, "sample.bin");
        await File.WriteAllTextAsync(path, "original payload");
        var quarantined = await _engine.ExecuteQuarantineAsync(Request(path));
        Assert.True(quarantined.Success, quarantined.Message);
        await File.WriteAllTextAsync(path, "new user file");

        var restored = await _engine.ExecuteRestoreAsync(quarantined.QuarantineId);

        Assert.False(restored.Success);
        Assert.Equal("new user file", await File.ReadAllTextAsync(path));
        Assert.True(File.Exists(quarantined.VaultContainerPath));
    }

    [Fact]
    public async Task TamperedCiphertext_DoesNotPublishCorruptRestoredFile()
    {
        var path = Path.Combine(_root, "sample.bin");
        await File.WriteAllBytesAsync(path, Enumerable.Repeat((byte)42, 160).ToArray());
        var quarantined = await _engine.ExecuteQuarantineAsync(Request(path));
        Assert.True(quarantined.Success, quarantined.Message);
        var container = await File.ReadAllBytesAsync(quarantined.VaultContainerPath);
        // Mutate the first ciphertext block without touching the final padding block.
        container[13 + sizeof(int) + sizeof(int) + 16 + sizeof(long)] ^= 1;
        await File.WriteAllBytesAsync(quarantined.VaultContainerPath, container);

        var restored = await _engine.ExecuteRestoreAsync(quarantined.QuarantineId);

        Assert.False(restored.Success);
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.GetFiles(_root, "*.restore.tmp"));
        Assert.True(File.Exists(quarantined.VaultContainerPath));
    }
}

public sealed class PolicyClassificationRegressionTests
{
    [Theory]
    [InlineData(FindingCategory.SuspiciousScript)]
    [InlineData(FindingCategory.UnsignedExecutable)]
    [InlineData(FindingCategory.MalwareSuspicion)]
    public void HeuristicFinding_WithConfirmedRiskLabel_IsWarnedOnly(FindingCategory category)
    {
        var finding = new SecurityFinding
        {
            Category = category, RiskLevel = RiskLevel.ConfirmedMalicious,
            RiskScore = 100, Status = FindingStatus.Active, ObjectPath = "sample.bin"
        };

        Assert.Equal(PolicyDecisionAction.Warn, new PolicyEngine().EvaluateFinding(finding).Action);
    }

    [Fact]
    public void IgnoredFinding_IsNotAutomaticallyQuarantined()
    {
        var finding = new SecurityFinding
        {
            Category = FindingCategory.KnownMalwareHash, RiskLevel = RiskLevel.ConfirmedMalicious,
            RiskScore = 100, Status = FindingStatus.Ignored, ObjectPath = "sample.bin"
        };

        Assert.Equal(PolicyDecisionAction.Allow, new PolicyEngine().EvaluateFinding(finding).Action);
    }
}

public sealed class SettingsViewModelRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisSettingsVmRegression_" + Guid.NewGuid().ToString("N"));
    private readonly bool _previousNetworkFlag = AegisPC.Core.Configuration.FeatureFlags.IsNetworkShieldActive;

    public SettingsViewModelRegressionTests() => Directory.CreateDirectory(_root);
    public void Dispose()
    {
        AegisPC.Core.Configuration.FeatureFlags.IsNetworkShieldActive = _previousNetworkFlag;
        Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public void LoadingPreferences_DoesNotWritePartialDefaultsOrMutateService()
    {
        var path = Path.Combine(_root, "settings.json");
        var settings = new SettingsService(path);
        settings.Current.IsFileProtectionEnabled = false;
        settings.Current.IsRansomwareShieldEnabled = false;
        settings.Current.IsRealTimeMonitoringEnabled = false;
        settings.Current.NotificationsEnabled = false;
        settings.Current.ScanScheduleEnabled = true;
        settings.Current.EnableAutoQuarantine = false;
        settings.Current.AutoQuarantineThreshold = 42;
        settings.Current.ScheduledScanHour = 19;
        settings.Current.ScanResourceMode = ScanResourceMode.Low;
        var ipc = new RecordingIpcClient();

        using var vm = new SettingsViewModel(settingsService: settings, ipcClient: ipc);

        Assert.False(vm.IsFileProtectionEnabled);
        Assert.False(vm.IsRansomwareShieldEnabled);
        Assert.False(vm.IsRealTimeMonitoringEnabled);
        Assert.False(vm.NotificationsEnabled);
        Assert.True(vm.ScanScheduleEnabled);
        Assert.False(vm.EnableAutoQuarantine);
        Assert.Equal(42, vm.AutoQuarantineThreshold);
        Assert.Equal(19, vm.ScheduledScanHour);
        Assert.Equal(ScanResourceMode.Low, vm.SelectedResourceMode);
        Assert.False(settings.Current.IsFileProtectionEnabled);
        Assert.False(settings.Current.IsRansomwareShieldEnabled);
        Assert.Equal(42, settings.Current.AutoQuarantineThreshold);
        Assert.False(File.Exists(path));
        Assert.Empty(ipc.Commands);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RejectedSettingsChange_RefreshesAuthoritativeServiceStatus(bool transportFails)
    {
        var ipc = new RecordingIpcClient();
        using var vm = new SettingsViewModel(ipcClient: ipc);
        var previousRequests = ipc.StatusRequests;
        ipc.AuthoritativeStatus = new ProtectionStatus
        {
            ProtectionLevel = "Aktif", IsServiceRunning = true, IsRealTimeEnabled = true,
            IsRansomwareShieldEnabled = true, EnableAutoQuarantine = true, AutoQuarantineThreshold = 85
        };
        ipc.ThrowOnCommand = transportFails;

        vm.EnableAutoQuarantine = false;

        // Fire-and-forget SaveSettingsAsync'in tamamlanmasını bekle (yoğun CPU altında yarış durumunu önler)
        for (int i = 0; i < 50 && (!vm.EnableAutoQuarantine || ipc.Commands.Count == 0); i++)
        {
            await Task.Delay(20);
        }

        Assert.True(vm.EnableAutoQuarantine);
        Assert.Equal(previousRequests + 1, ipc.StatusRequests);
        Assert.Single(ipc.Commands);
        Assert.Equal(ServiceCommandType.UpdateSettings, ipc.Commands[0].CommandType);
    }

    [Fact]
    public void DisposedViewModel_UnsubscribesFromServiceUpdates()
    {
        var ipc = new RecordingIpcClient();
        var vm = new SettingsViewModel(ipcClient: ipc);
        vm.Dispose();

        ipc.AuthoritativeStatus = new ProtectionStatus { ProtectionLevel = "Kapalı", IsRealTimeEnabled = false };
        ipc.PublishStatus();

        Assert.True(vm.IsFileProtectionEnabled);
    }

    [Fact]
    public void ScheduleAndResourcePreferences_AreIncludedInServiceSettingsPatch()
    {
        var ipc = new RecordingIpcClient();
        using var vm = new SettingsViewModel(ipcClient: ipc);

        vm.SelectedScanPeriod = vm.ScanPeriods[5];
        vm.SelectedScanHourString = "19:00";
        vm.SelectedResourceModeItem = vm.ResourceModes.Single(m => m.Mode == ScanResourceMode.Low);

        using var payload = JsonDocument.Parse(ipc.Commands.Last().Payload!);
        Assert.Equal(0, payload.RootElement.GetProperty("ScheduledScanIntervalHours").GetInt32());
        Assert.Equal(19, payload.RootElement.GetProperty("ScheduledScanHour").GetInt32());
        Assert.Equal((int)ScanResourceMode.Low, payload.RootElement.GetProperty("ScanResourceMode").GetInt32());
    }

    private sealed class RecordingIpcClient : IServiceIpcClient
    {
        public bool IsConnected => true;
        public int StatusRequests { get; private set; }
        public bool ThrowOnCommand { get; set; }
        public ProtectionStatus? AuthoritativeStatus { get; set; }
        public System.Collections.Generic.List<ServiceCommand> Commands { get; } = new();
        public event Action<ProtectionStatus>? StatusChanged;
        public event Action<ThreatNotification>? ThreatDetected { add { } remove { } }
        public Task ConnectAsync() => Task.CompletedTask;
        public Task SendCommandAsync(ServiceCommand command)
        {
            Commands.Add(command);
            return ThrowOnCommand ? Task.FromException(new IOException("Simulated pipe failure")) : Task.CompletedTask;
        }
        public Task<ProtectionStatus> GetStatusAsync()
        {
            StatusRequests++;
            PublishStatus();
            return Task.FromResult(AuthoritativeStatus ?? new ProtectionStatus { ProtectionLevel = "Bekleniyor" });
        }
        public void PublishStatus()
        {
            if (AuthoritativeStatus != null) StatusChanged?.Invoke(AuthoritativeStatus);
        }
        public void Dispose() { }
    }
}
