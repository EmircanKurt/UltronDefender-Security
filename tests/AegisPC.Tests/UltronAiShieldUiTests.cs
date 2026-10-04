using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Threading;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using ButtonBase = System.Windows.Controls.Primitives.ButtonBase;
using AegisPC.App.Controls;
using AegisPC.App.Services;
using AegisPC.App.ViewModels;
using AegisPC.Core.Models;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert confirmation/IPC/UI regressions; no real service, process or protection configuration is changed.</summary>
public sealed class UltronAiShieldUiTests : IDisposable
{
    private readonly bool _previousNetworkFlag = AegisPC.Core.Configuration.FeatureFlags.IsNetworkShieldActive;

    /// <summary>Restores only the in-memory feature preference observed by this inert fixture.</summary>
    public void Dispose() => AegisPC.Core.Configuration.FeatureFlags.IsNetworkShieldActive = _previousNetworkFlag;

    [Theory]
    [InlineData(false, false, 1)]
    [InlineData(true, false, 2)]
    public async Task EitherRefusal_SendsNoDisableAndKeepsObservedIndicator(bool first, bool second, int prompts)
    {
        var ipc = new FixtureIpc();
        var confirmation = new Confirmation(first, second);
        using var vm = new SettingsViewModel(ipcClient: ipc, disableConfirmation: confirmation);
        await vm.ToggleUltronAiCommand.ExecuteAsync(null);
        Assert.True(vm.IsUltronAiEnabled);
        Assert.Equal(prompts, confirmation.Calls);
        Assert.Empty(ipc.Commands);
        Assert.Contains("iptal", vm.StatusMessage);
    }

    [Fact]
    public async Task BothApprovals_ChangeOnlyOptionalAiAfterServiceAck()
    {
        var ipc = new FixtureIpc();
        var confirmation = new Confirmation(true, true);
        using var vm = new SettingsViewModel(ipcClient: ipc, disableConfirmation: confirmation);
        await vm.ToggleUltronAiCommand.ExecuteAsync(null);
        Assert.Equal(2, confirmation.Calls);
        Assert.Equal(ServiceCommandType.DisableUltronAi, Assert.Single(ipc.Commands).CommandType);
        Assert.False(vm.IsUltronAiEnabled);
        Assert.True(vm.IsUltronAiStatusVerified);
        Assert.True(ipc.Status.IsRealTimeEnabled);
        Assert.True(ipc.Status.IsRansomwareShieldEnabled);
        Assert.True(vm.IsProtectionWarningVisible);
        Assert.Contains("diğer", vm.StatusMessage);
        Assert.All(confirmation.Messages, message => Assert.DoesNotContain("her türlü", message));
    }

    [Fact]
    public async Task Enable_DoesNotAskForDisableConsent()
    {
        var ipc = new FixtureIpc { Status = Status(false) };
        var confirmation = new Confirmation(false, false);
        using var vm = new SettingsViewModel(ipcClient: ipc, disableConfirmation: confirmation);
        await vm.ToggleUltronAiCommand.ExecuteAsync(null);
        Assert.Equal(0, confirmation.Calls);
        Assert.Equal(ServiceCommandType.EnableUltronAi, Assert.Single(ipc.Commands).CommandType);
        Assert.True(vm.IsUltronAiEnabled);
    }

    [Fact]
    public async Task PendingSecondApproval_DoesNotFlipIndicatorOrSendRequest()
    {
        var second = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var ipc = new FixtureIpc();
        var confirmation = new Confirmation(true, true) { PendingSecond = second.Task };
        using var vm = new SettingsViewModel(ipcClient: ipc, disableConfirmation: confirmation);
        var request = vm.ToggleUltronAiCommand.ExecuteAsync(null);
        Assert.True(vm.IsUltronAiEnabled);
        Assert.Empty(ipc.Commands);
        Assert.False(vm.ToggleUltronAiCommand.CanExecute(null));
        second.SetResult(true);
        await request.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.False(vm.IsUltronAiEnabled);
    }

    [Fact]
    public async Task RejectedServiceChange_DoesNotClaimDisabled()
    {
        var ipc = new FixtureIpc { ApplyChanges = false };
        using var vm = new SettingsViewModel(ipcClient: ipc, disableConfirmation: new Confirmation(true, true));
        await vm.ToggleUltronAiCommand.ExecuteAsync(null);
        Assert.True(vm.IsUltronAiEnabled);
        Assert.Contains("doğrulanamadı", vm.StatusMessage);
        Assert.DoesNotContain("kapatıldı", vm.StatusMessage);
    }

    [Theory]
    [InlineData("legacy")]
    [InlineData("stale")]
    [InlineData("disconnected")]
    public async Task UnverifiedService_DoesNotRequestChangeOrConsent(string condition)
    {
        var ipc = new FixtureIpc();
        if (condition == "legacy") { ipc.Status.IsUltronAiEnabled = null; ipc.Status.Health = null; }
        if (condition == "stale") ipc.Status.Health = new ProtectionHealthSnapshot { CapturedAtUtc = DateTime.UtcNow.AddMinutes(-1) };
        if (condition == "disconnected") ipc.IsConnected = false;
        var confirmation = new Confirmation(true, true);
        using var vm = new SettingsViewModel(ipcClient: ipc, disableConfirmation: confirmation);
        await vm.ToggleUltronAiCommand.ExecuteAsync(null);
        Assert.False(vm.IsUltronAiStatusVerified);
        Assert.Equal(0, confirmation.Calls);
        Assert.Empty(ipc.Commands);
        Assert.Contains("değiştirilmedi", vm.StatusMessage);
        Assert.True(vm.IsProtectionWarningVisible);
    }

    [Fact]
    public async Task Refresh_UsesNewServiceObservationAndDoesNotStartLocalProtection()
    {
        var ipc = new FixtureIpc { IsConnected = false };
        using var vm = new SettingsViewModel(ipcClient: ipc);
        Assert.Contains("bağlanılamıyor", vm.ProtectionWarningText);
        ipc.IsConnected = true;
        await vm.RefreshProtectionStatusCommand.ExecuteAsync(null);
        Assert.True(vm.IsUltronAiStatusVerified);
        Assert.False(vm.IsProtectionWarningVisible);
        Assert.Empty(ipc.Commands);
    }

    [Fact]
    public void FreshDegradedHealth_DoesNotHideCoverageWarning()
    {
        var ipc = new FixtureIpc();
        ipc.Status.Health!.State = ProtectionHealthState.Degraded;
        using var vm = new SettingsViewModel(ipcClient: ipc);
        Assert.True(vm.IsProtectionStatusVerified);
        Assert.True(vm.IsProtectionWarningVisible);
        Assert.Contains("kısmi", vm.ProtectionWarningText);
    }

    [Fact]
    public void ObservedSwitch_ClickRunsCommandWithoutOptimisticVisualToggle() => RunSta(() =>
    {
        var command = new RecordingCommand();
        var control = new ObservedProtectionSwitch { IsChecked = true, Command = command };
        typeof(ButtonBase).GetMethod("OnClick", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(control, null);
        Assert.True(control.IsChecked);
        Assert.Equal(1, command.Calls);
    });

    private static ProtectionStatus Status(bool enabled = true) => new()
    {
        IsServiceRunning = true, IsRealTimeEnabled = true, IsRansomwareShieldEnabled = true,
        IsUltronAiEnabled = enabled, ProtectionLevel = "Inert fixture", RequestId = Guid.NewGuid(),
        Health = new ProtectionHealthSnapshot { CapturedAtUtc = DateTime.UtcNow, State = ProtectionHealthState.Healthy }
    };

    [Fact]
    public void ObservedSwitch_AutomationUsesConsentCommandWithoutChangingIndicator() => RunSta(() =>
    {
        var command = new RecordingCommand();
        var control = new ObservedProtectionSwitch { IsChecked = true, Command = command };
        var peer = UIElementAutomationPeer.CreatePeerForElement(control);
        Assert.NotNull(peer);
        var toggle = Assert.IsAssignableFrom<IToggleProvider>(peer.GetPattern(PatternInterface.Toggle));
        toggle.Toggle();
        Assert.True(control.IsChecked);
        Assert.Equal(1, command.Calls);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NetworkDeniedOrOffline_DoesNotPublishOptimisticEnabledState(bool connected)
    {
        var ipc = new FixtureIpc { IsConnected = connected, ApplyChanges = false };
        using var vm = new SettingsViewModel(ipcClient: ipc);
        await InvokeNetworkChange(vm, true);
        Assert.False(vm.IsNetworkProtectionEnabled);
        Assert.Contains("doğrulanamadı", vm.StatusMessage);
        Assert.DoesNotContain("açtığı doğrulandı", vm.StatusMessage);
    }

    [Fact]
    public async Task NetworkPendingRequest_KeepsObservedIndicatorUntilAck()
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ipc = new FixtureIpc { CommandCompletion = completion.Task };
        using var vm = new SettingsViewModel(ipcClient: ipc);
        var request = InvokeNetworkChange(vm, true);
        Assert.False(vm.IsNetworkProtectionEnabled);
        completion.SetResult();
        await request.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.True(vm.IsNetworkProtectionEnabled);
        Assert.Equal(ServiceCommandType.EnableNetworkProtection, Assert.Single(ipc.Commands).CommandType);
        Assert.Contains("tüm ağ akışı incelemesi değildir", vm.StatusMessage);
    }

    private static Task InvokeNetworkChange(SettingsViewModel vm, bool enabled) =>
        (Task)typeof(SettingsViewModel).GetMethod("RequestNetworkProtectionChangeAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(vm, new object[] { enabled })!;

    private sealed class Confirmation(bool first, bool second) : IProtectionDisableConfirmation
    {
        internal int Calls { get; private set; }
        internal List<string> Messages { get; } = new();
        internal Task<bool>? PendingSecond { get; init; }
        /// <inheritdoc />
        public Task<bool> ConfirmAsync(string title, string message)
        {
            Calls++;
            Messages.Add(message);
            return Calls == 1 ? Task.FromResult(first) : PendingSecond ?? Task.FromResult(second);
        }
    }

    private sealed class FixtureIpc : IServiceIpcClient
    {
        /// <inheritdoc />
        public bool IsConnected { get; set; } = true;
        internal ProtectionStatus Status { get; set; } = UltronAiShieldUiTests.Status();
        internal bool ApplyChanges { get; init; } = true;
        internal Task CommandCompletion { get; init; } = Task.CompletedTask;
        internal List<ServiceCommand> Commands { get; } = new();
        /// <inheritdoc />
        public event Action<ProtectionStatus>? StatusChanged { add { } remove { } }
        /// <inheritdoc />
        public event Action<ThreatNotification>? ThreatDetected { add { } remove { } }
        /// <inheritdoc />
        public Task ConnectAsync() => Task.CompletedTask;
        /// <inheritdoc />
        public Task<ProtectionStatus> GetStatusAsync() => Task.FromResult(Status);
        /// <inheritdoc />
        public async Task SendCommandAsync(ServiceCommand command)
        {
            Commands.Add(command);
            await CommandCompletion;
            if (!ApplyChanges) return;
            if (command.CommandType is ServiceCommandType.EnableNetworkProtection or ServiceCommandType.DisableNetworkProtection)
                Status.IsNetworkProtectionEnabled = command.CommandType == ServiceCommandType.EnableNetworkProtection;
            else Status.IsUltronAiEnabled = command.CommandType == ServiceCommandType.EnableUltronAi;
        }
        /// <inheritdoc />
        public void Dispose() { }
    }

    private sealed class RecordingCommand : ICommand
    {
        internal int Calls { get; private set; }
        /// <inheritdoc />
        public event EventHandler? CanExecuteChanged { add { } remove { } }
        /// <inheritdoc />
        public bool CanExecute(object? parameter) => true;
        /// <inheritdoc />
        public void Execute(object? parameter) => Calls++;
    }

    private static void RunSta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception exception) { error = exception; }
            finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)));
        if (error != null) ExceptionDispatchInfo.Capture(error).Throw();
    }
}
