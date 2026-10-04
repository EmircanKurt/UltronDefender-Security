using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using AegisPC.App.Services;
using AegisPC.App.Startup;
using AegisPC.App.ViewModels;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.RealTime;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ProtectedFolder = AegisPC.App.ViewModels.ProtectedFolder;

namespace AegisPC.Tests;

/// <summary>Inert IPC/UI infrastructure regressions; no native protection engine, live service or malware is started.</summary>
public sealed class ServiceOwnedRansomwareUiTests : IDisposable
{
    private readonly string _fixtureRoot = Path.Combine(Path.GetTempPath(), "UltronUiOwnership-" + Guid.NewGuid().ToString("N"));
    private readonly bool _previousNetworkFlag = AegisPC.Core.Configuration.FeatureFlags.IsNetworkShieldActive;

    [Fact]
    public void Constructor_DoesNotStartInjectedEngineOrInventProtection()
    {
        var engine = DispatchProxy.Create<IRansomwareProtectionEngine, RejectLocalOperationProxy>();
        using var vm = new RansomwareShieldViewModel(ransomwareEngine: engine);
        Assert.False(vm.IsShieldEnabled);
        Assert.False(vm.IsStatusVerified);
        Assert.Equal(0, vm.CanaryFileCount);
        Assert.Equal(0, vm.ProtectedFolderCount);
        Assert.Equal("Doğrulanmadı", vm.CanaryFileCountText);
        Assert.Empty(vm.ProtectedFolders);
        Assert.Empty(vm.AllowedApplications);
        Assert.Empty(vm.RecentEvents);
        Assert.Equal(0, ((RejectLocalOperationProxy)(object)engine).OperationCount);
    }

    [Fact]
    public void FreshObservation_UsesAggregateCountsWithoutInventingContainment()
    {
        var status = Status(enabled: true);
        status.RansomwareCanaryFileCount = 3;
        status.RansomwareProtectedFolderCount = 2;
        var ipc = new FixtureIpc { Status = status };
        using var vm = new RansomwareShieldViewModel(ipcClient: ipc);
        Assert.True(vm.IsStatusVerified);
        Assert.True(vm.IsShieldEnabled);
        Assert.Equal(3, vm.CanaryFileCount);
        Assert.Equal("2", vm.ProtectedFolderCountText);
        Assert.Equal(0, vm.TotalBlockedCount);
        Assert.Equal("Doğrulanmadı", vm.TotalBlockedCountText);
        Assert.Empty(vm.ProtectedFolders);
        Assert.Contains("ön-yazma engelleme değildir", vm.ShieldStatusText);
    }

    [Fact]
    public void PartialHealth_DoesNotClaimUnqualifiedProtection()
    {
        var status = Status(enabled: true);
        status.Health!.State = ProtectionHealthState.Degraded;
        using var vm = new RansomwareShieldViewModel(ipcClient: new FixtureIpc { Status = status });
        Assert.Contains("kısmi", vm.ShieldStatusText);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void MissingOrStaleHealth_CannotClaimShieldActive(bool missing)
    {
        var status = Status(enabled: true);
        status.Health = missing ? null : new ProtectionHealthSnapshot { CapturedAtUtc = DateTime.UtcNow.AddMinutes(-1), State = ProtectionHealthState.Healthy };
        using var vm = new RansomwareShieldViewModel(ipcClient: new FixtureIpc { Status = status });
        Assert.False(vm.IsStatusVerified);
        Assert.False(vm.IsShieldEnabled);
        Assert.Equal("Doğrulanmadı", vm.CanaryFileCountText);
    }

    [Fact]
    public void DisconnectedObservation_RevokesVerifiedUiState()
    {
        var ipc = new FixtureIpc { Status = Status(enabled: true) };
        using var vm = new RansomwareShieldViewModel(ipcClient: ipc);
        ipc.IsConnected = false;
        ipc.Publish();
        Assert.False(vm.IsStatusVerified);
        Assert.False(vm.IsShieldEnabled);
    }

    [Fact]
    public async Task Toggle_WaitsForServiceStateInsteadOfOptimisticallyEnabling()
    {
        var pendingWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ipc = new FixtureIpc { Status = Status(enabled: false), CommandCompletion = pendingWrite.Task };
        var settings = new SettingsService(FixtureSettingsPath());
        using var vm = new RansomwareShieldViewModel(settingsService: settings, ipcClient: ipc);
        var toggle = vm.ToggleShieldCommand.ExecuteAsync(null);
        Assert.False(vm.IsShieldEnabled);
        Assert.Equal(ServiceCommandType.EnableRansomwareShield, Assert.Single(ipc.Commands).CommandType);
        ipc.Status = Status(enabled: true);
        pendingWrite.SetResult();
        await toggle.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.True(vm.IsShieldEnabled);
        Assert.True(vm.IsStatusVerified);
        Assert.Contains("durumu doğrulandı", vm.StatusMessage);
        Assert.False(File.Exists(FixtureSettingsPath()));
    }

    [Fact]
    public async Task DeniedToggle_LeavesObservedStateAndDoesNotClaimSuccess()
    {
        var ipc = new FixtureIpc { Status = Status(enabled: false) };
        using var vm = new RansomwareShieldViewModel(ipcClient: ipc);
        await vm.ToggleShieldCommand.ExecuteAsync(null);
        Assert.False(vm.IsShieldEnabled);
        Assert.Contains("doğrulanmadı", vm.StatusMessage);
        Assert.DoesNotContain("durumu doğrulandı", vm.StatusMessage);
    }

    [Fact]
    public async Task UncorrelatedStatus_CannotAcknowledgeProtectionCommand()
    {
        var ipc = new FixtureIpc { Status = Status(enabled: false) };
        using var vm = new RansomwareShieldViewModel(ipcClient: ipc);
        ipc.AfterCommand = () => { ipc.Status = Status(enabled: true); ipc.Status.RequestId = Guid.Empty; };
        await vm.ToggleShieldCommand.ExecuteAsync(null);
        Assert.Contains("doğrulanmadı", vm.StatusMessage);
        Assert.DoesNotContain("durumu doğrulandı", vm.StatusMessage);
    }

    [Fact]
    public async Task OfflineToggle_DoesNotSendCommandOrWritePreference()
    {
        var ipc = new FixtureIpc { IsConnected = false, Status = Status(enabled: true) };
        var settings = new SettingsService(FixtureSettingsPath());
        bool before = settings.Current.IsRansomwareShieldEnabled;
        using var vm = new RansomwareShieldViewModel(settingsService: settings, ipcClient: ipc);
        await vm.ToggleShieldCommand.ExecuteAsync(null);
        Assert.Empty(ipc.Commands);
        Assert.Equal(before, settings.Current.IsRansomwareShieldEnabled);
        Assert.False(File.Exists(FixtureSettingsPath()));
        Assert.False(vm.IsStatusVerified);
    }

    [Fact]
    public void UnavailableFolderAndAllowlistManagement_DoesNotMutateUiCollections()
    {
        using var vm = new RansomwareShieldViewModel();
        var folder = new ProtectedFolder { Name = "Inert fixture", Path = "fixture-only" };
        var app = new AllowedRansomwareApplication { ApplicationName = "Inert fixture", ExecutablePath = "fixture-only.exe" };
        vm.ProtectedFolders.Add(folder);
        vm.AllowedApplications.Add(app);
        vm.AddFolderCommand.Execute(null);
        vm.AddAllowedAppCommand.Execute(null);
        vm.RemoveFolderCommand.Execute(folder);
        vm.RemoveAllowedAppCommand.Execute(app);
        Assert.Same(folder, Assert.Single(vm.ProtectedFolders));
        Assert.Same(app, Assert.Single(vm.AllowedApplications));
        Assert.Contains("hiçbir liste veya dosya değiştirilmedi", vm.StatusMessage);
    }

    [Fact]
    public async Task Facade_RejectsAllLocalMutationAndContainmentOperations()
    {
        using var client = new ServiceRansomwareClient(new FixtureIpc());
        Assert.Throws<NotSupportedException>(client.StartShield);
        Assert.Throws<NotSupportedException>(client.StopShield);
        Assert.Throws<NotSupportedException>(() => client.AddProtectedDirectory("fixture-only"));
        Assert.Throws<NotSupportedException>(() => client.RemoveProtectedDirectory("fixture-only"));
        Assert.Throws<NotSupportedException>(() => client.AddAllowedApplication("fixture-only.exe"));
        Assert.Throws<NotSupportedException>(() => client.RemoveAllowedApplication("fixture-only.exe"));
        Assert.Throws<NotSupportedException>(client.CleanupCanaryFiles);
        await Assert.ThrowsAsync<NotSupportedException>(() => client.EvaluateAndContainThreatAsync("fixture-only", "inert", 0));
        Assert.False(client.IsApplicationAllowed("fixture-only.exe"));
        Assert.Empty(client.ProtectedDirectories);
        Assert.Empty(client.AllowedApplications);
    }

    [Fact]
    public void Facade_UsesOnlyFreshConnectedMetadataAndUnsubscribes()
    {
        var status = Status(enabled: true);
        status.RansomwareCanaryFileCount = 5;
        var ipc = new FixtureIpc { Status = status };
        var client = new ServiceRansomwareClient(ipc);
        ipc.Publish();
        Assert.True(client.IsShieldActive);
        Assert.Equal(5, client.CanaryFileCount);
        Assert.Equal(0, client.TotalBlockedAttempts);
        ipc.IsConnected = false;
        Assert.False(client.IsShieldActive);
        Assert.Equal(0, client.CanaryFileCount);
        client.Dispose();
        ipc.IsConnected = true;
        ipc.Publish();
        Assert.False(client.IsShieldActive);
        Assert.Equal(0, client.CanaryFileCount);
    }

    [Fact]
    public void ProductionDi_BindsRansomwareEngineToServiceFacadeOnly()
    {
        var services = new ServiceCollection();
        ServiceRegistration.RegisterServices(services);
        var descriptor = Assert.Single(services, item => item.ServiceType == typeof(IRansomwareProtectionEngine));
        Assert.Equal(typeof(ServiceRansomwareClient), descriptor.ImplementationType);
    }

    [Fact]
    public void OfflineSettingsToggles_NeverStartEnginesOrPersistOptimisticState()
    {
        var engine = DispatchProxy.Create<IRansomwareProtectionEngine, RejectLocalOperationProxy>();
        var background = DispatchProxy.Create<IBackgroundProtectionService, RejectLocalOperationProxy>();
        var ipc = new FixtureIpc { IsConnected = false };
        var settings = new SettingsService(FixtureSettingsPath());
        settings.Current.IsFileProtectionEnabled = false;
        settings.Current.IsRansomwareShieldEnabled = false;
        using var vm = new SettingsViewModel(settingsService: settings, backgroundProtectionService: background,
            ransomwareProtectionEngine: engine, ipcClient: ipc);
        vm.IsFileProtectionEnabled = true;
        vm.IsRansomwareShieldEnabled = true;
        Assert.False(vm.IsFileProtectionEnabled);
        Assert.False(vm.IsRansomwareShieldEnabled);
        Assert.False(vm.IsProtectionStatusVerified);
        Assert.False(settings.Current.IsFileProtectionEnabled);
        Assert.False(settings.Current.IsRansomwareShieldEnabled);
        Assert.False(File.Exists(FixtureSettingsPath()));
        Assert.Empty(ipc.Commands);
        Assert.Equal(0, ((RejectLocalOperationProxy)(object)engine).OperationCount);
        Assert.Equal(0, ((RejectLocalOperationProxy)(object)background).OperationCount);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SettingsToggle_WaitsForCorrelatedObservedStateAndDoesNotSaveUiPreference(bool ransomware)
    {
        var pendingWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ipc = new FixtureIpc { Status = Status(enabled: false), CommandCompletion = pendingWrite.Task };
        var settings = new SettingsService(FixtureSettingsPath());
        using var vm = new SettingsViewModel(settingsService: settings, ipcClient: ipc);
        var task = InvokeSettingsChange(vm, ransomware, true);
        Assert.False(ransomware ? vm.IsRansomwareShieldEnabled : vm.IsFileProtectionEnabled);
        Assert.False(File.Exists(FixtureSettingsPath()));
        ipc.Status = Status(enabled: true);
        pendingWrite.SetResult();
        await task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.True(ransomware ? vm.IsRansomwareShieldEnabled : vm.IsFileProtectionEnabled);
        Assert.True(vm.IsProtectionStatusVerified);
        Assert.Contains("durumu doğrulandı", vm.StatusMessage);
        Assert.False(File.Exists(FixtureSettingsPath()));
    }

    [Fact]
    public async Task RejectedSettingsToggle_RestoresObservedStateWithoutPersisting()
    {
        var ipc = new FixtureIpc { Status = Status(enabled: false) };
        var settings = new SettingsService(FixtureSettingsPath());
        using var vm = new SettingsViewModel(settingsService: settings, ipcClient: ipc);
        await InvokeSettingsChange(vm, ransomware: true, enabled: true);
        Assert.False(vm.IsRansomwareShieldEnabled);
        Assert.False(settings.Current.IsRansomwareShieldEnabled);
        Assert.False(File.Exists(FixtureSettingsPath()));
        Assert.Contains("doğrulanmadı", vm.StatusMessage);
    }

    private static Task InvokeSettingsChange(SettingsViewModel vm, bool ransomware, bool enabled) =>
        (Task)typeof(SettingsViewModel).GetMethod("RequestServiceProtectionChangeAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(vm, new object[] { ransomware, enabled })!;

    private string FixtureSettingsPath() => Path.Combine(_fixtureRoot, "settings.json");

    private static ProtectionStatus Status(bool enabled) => new()
    {
        ProtectionLevel = "Inert fixture", IsServiceRunning = true, IsRealTimeEnabled = enabled,
        IsRansomwareShieldEnabled = enabled, RequestId = Guid.NewGuid(),
        Health = new ProtectionHealthSnapshot { CapturedAtUtc = DateTime.UtcNow, State = ProtectionHealthState.Healthy }
    };

    /// <summary>Removes only this instance's private settings fixture if a tested regression unexpectedly wrote it.</summary>
    public void Dispose()
    {
        AegisPC.Core.Configuration.FeatureFlags.IsNetworkShieldActive = _previousNetworkFlag;
        if (Directory.Exists(_fixtureRoot)) Directory.Delete(_fixtureRoot, recursive: true);
    }

    private sealed class FixtureIpc : IServiceIpcClient
    {
        /// <inheritdoc />
        public bool IsConnected { get; set; } = true;
        internal ProtectionStatus Status { get; set; } = ServiceOwnedRansomwareUiTests.Status(enabled: false);
        internal Task CommandCompletion { get; init; } = Task.CompletedTask;
        internal Action? AfterCommand { get; set; }
        internal List<ServiceCommand> Commands { get; } = new();
        /// <inheritdoc />
        public event Action<ProtectionStatus>? StatusChanged;
        /// <inheritdoc />
        public event Action<ThreatNotification>? ThreatDetected { add { } remove { } }
        /// <inheritdoc />
        public Task ConnectAsync() => Task.CompletedTask;
        /// <inheritdoc />
        public async Task SendCommandAsync(ServiceCommand command)
        { Commands.Add(command); await CommandCompletion; AfterCommand?.Invoke(); }
        /// <inheritdoc />
        public Task<ProtectionStatus> GetStatusAsync() => Task.FromResult(Status);
        internal void Publish() => StatusChanged?.Invoke(Status);
        /// <inheritdoc />
        public void Dispose() { }
    }

    /// <summary>Throws on any local engine operation; mere injection must never touch native protection.</summary>
    public class RejectLocalOperationProxy : DispatchProxy
    {
        /// <summary>Number of unexpected protection operations attempted.</summary>
        public int OperationCount { get; private set; }
        /// <summary>Counts and rejects all engine calls so no real OS behavior can escape a fixture.</summary>
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        { OperationCount++; throw new InvalidOperationException("Local protection must not be used by the service-owned UI."); }
    }
}
