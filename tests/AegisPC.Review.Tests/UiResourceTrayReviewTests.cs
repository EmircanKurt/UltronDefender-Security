using System.IO;
using System.Text.Json;
using System.Xml.Linq;
using AegisPC.App.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Service.IPC;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert policy/approval/persistence and XAML source regressions; no live shield, service, malware or host settings.</summary>
public sealed class UiResourceTrayReviewTests
{
    /// <summary>Suitable idle machines get useful 2/4 GiB upper budgets, not minimum resident allocations.</summary>
    [Theory]
    [InlineData(ScanType.Quick, 2048)]
    [InlineData(ScanType.Full, 4096)]
    public void IdleCapableMachineHasScanSpecificBudget(ScanType type, int expectedMiB)
    {
        var profile = ScanResourceProfile.Create(ScanResourceMode.Auto, false, 8, 16L << 30, 10, 45, scanType: type);
        Assert.Equal(expectedMiB * 1048576L, profile.MaxMemoryBudgetBytes);
        Assert.Equal(60, profile.CpuTargetPercent);
        Assert.Contains("üst bütçesi", profile.SummaryText);
    }

    /// <summary>Full scans yield under pressure or low hardware; artificial 4 GiB allocation is never required.</summary>
    [Theory]
    [InlineData(16, 80, 50, false)]
    [InlineData(16, 20, 80, false)]
    [InlineData(16, 20, 50, true)]
    [InlineData(4, 10, 30, false)]
    [InlineData(16, double.NaN, double.NaN, false)]
    public void PressureAndWeakHardwareCannotForceFourGiB(int ramGiB, double cpu, double memory, bool battery)
    {
        var profile = ScanResourceProfile.Create(ScanResourceMode.Auto, false, 8, (long)ramGiB << 30, cpu, memory, battery, ScanType.Full);
        Assert.True(profile.MaxMemoryBudgetBytes <= 2L << 30);
        Assert.InRange(profile.Concurrency, 1, profile.MaximumConcurrency);
    }

    /// <summary>Durable intent precedes stop, expiry restores once, and fake clock avoids actual waiting/native calls.</summary>
    [Theory]
    [InlineData(10)] [InlineData(60)] [InlineData(300)]
    public async Task PauseRestoresAtItsExactDeadline(int minutes)
    {
        var fixture = new PauseFixture();
        await fixture.Controller.PauseAsync(minutes, false);
        Assert.False(fixture.Enabled);
        Assert.Equal(new[] { "save-pause", "disable", "save-pause" }, fixture.Events);
        Assert.False(fixture.State!.RestoreImmediately);
        Assert.Equal(fixture.Clock.Now.UtcDateTime.AddMinutes(minutes), fixture.State!.ResumeAtUtc);
        fixture.Clock.Now += TimeSpan.FromMinutes(minutes) - TimeSpan.FromSeconds(1);
        Assert.False(await fixture.Controller.RecoverDueAsync());
        fixture.Clock.Now += TimeSpan.FromSeconds(1);
        Assert.True(await fixture.Controller.RecoverDueAsync());
        Assert.True(fixture.Enabled);
        Assert.Null(fixture.State);
        Assert.False(await fixture.Controller.RecoverDueAsync());
    }

    /// <summary>Next-service-start restoration is sticky across an initial failed start; UI lifetime is irrelevant.</summary>
    [Fact]
    public async Task ServiceRestartRestorationRetriesAfterFailure()
    {
        var fixture = new PauseFixture();
        await fixture.Controller.PauseAsync(0, true);
        Assert.False(await fixture.Controller.RecoverDueAsync());
        fixture.FailEnable = true;
        await Assert.ThrowsAsync<IOException>(() => fixture.Controller.RecoverDueAsync(true));
        Assert.NotNull(fixture.State);
        fixture.FailEnable = false;
        Assert.True(await fixture.Controller.RecoverDueAsync());
    }

    /// <summary>Invalid/nested requests cannot extend or mutate current protection.</summary>
    [Theory]
    [InlineData(-1, false)] [InlineData(0, false)] [InlineData(11, false)]
    [InlineData(301, false)] [InlineData(10, true)]
    public async Task UnsupportedDurationDoesNotMutate(int minutes, bool restart)
    {
        var fixture = new PauseFixture();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => fixture.Controller.PauseAsync(minutes, restart));
        Assert.Empty(fixture.Events);
    }

    /// <summary>Pre-stop persistence failure leaves the active file shield unchanged.</summary>
    [Fact]
    public async Task PersistenceFailureBeforeStopDoesNotDisable()
    {
        var fixture = new PauseFixture { FailSave = true };
        await Assert.ThrowsAsync<IOException>(() => fixture.Controller.PauseAsync(10, false));
        Assert.True(fixture.Enabled);
        Assert.Empty(fixture.Events);
    }

    /// <summary>A partially failing stop/re-enable retains restoration; it cannot falsely report containment success.</summary>
    [Fact]
    public async Task FailedStopAndRecoveryKeepDurableIntent()
    {
        var fixture = new PauseFixture { FailStop = true, FailEnable = true };
        await Assert.ThrowsAsync<AggregateException>(() => fixture.Controller.PauseAsync(10, false));
        Assert.NotNull(fixture.State);
        fixture.FailEnable = false;
        Assert.True(fixture.State!.RestoreImmediately);
        Assert.True(await fixture.Controller.RecoverDueAsync());
    }

    /// <summary>A service interruption between the durable intent and successful completion restores on recovery.</summary>
    [Fact]
    public async Task InterruptedPauseRestoresBeforeItsDeadline()
    {
        var fixture = new PauseFixture
        {
            Enabled = false,
            State = new() { ResumeAtUtc = new DateTime(2026, 10, 8, 13, 0, 0, DateTimeKind.Utc), RestoreImmediately = true }
        };
        Assert.True(await fixture.Controller.RecoverDueAsync());
        Assert.True(fixture.Enabled);
        Assert.Null(fixture.State);
    }

    /// <summary>A failed completion write compensates immediately rather than claiming a confirmed timed pause.</summary>
    [Fact]
    public async Task CompletionPersistenceFailureReopensProtection()
    {
        var fixture = new PauseFixture { FailSaveNumber = 2 };
        await Assert.ThrowsAsync<IOException>(() => fixture.Controller.PauseAsync(10, false));
        Assert.True(fixture.Enabled);
        Assert.Null(fixture.State);
    }

    /// <summary>Manual off cancels scheduled restoration instead of unexpectedly re-enabling a user-disabled shield.</summary>
    [Fact]
    public async Task ManualChoiceOverridesPauseAndRepeatedPauseCannotExtend()
    {
        var fixture = new PauseFixture();
        await fixture.Controller.PauseAsync(10, false);
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Controller.PauseAsync(60, false));
        await fixture.Controller.SetManualEnabledAsync(false);
        fixture.Clock.Now += TimeSpan.FromHours(1);
        Assert.False(await fixture.Controller.RecoverDueAsync());
        Assert.False(fixture.Enabled);
    }

    /// <summary>Both prompts require explicit consent; fake IPC records transmission without native actions.</summary>
    [Theory]
    [InlineData(false, false, 0)] [InlineData(true, false, 0)] [InlineData(true, true, 1)]
    public async Task TwoApprovalsPrecedeTrayMutation(bool first, bool second, int mutations)
    {
        using var ipc = new FakeIpc();
        var confirmation = new Confirmation(first, second);
        bool applied = await new TrayProtectionActions(ipc, confirmation).PauseAsync(10);
        Assert.Equal(mutations, ipc.Mutations);
        Assert.Equal(mutations == 1, applied);
        Assert.Equal(first ? 2 : 1, confirmation.Count);
    }

    /// <summary>Older/unconnected services do not receive a new control and no optimistic local engine fallback runs.</summary>
    [Theory]
    [InlineData(false, true)] [InlineData(true, false)]
    public async Task MissingServiceCapabilityBlocksBeforeConfirmation(bool connected, bool supported)
    {
        using var ipc = new FakeIpc { IsConnected = connected, Supported = supported };
        var confirmation = new Confirmation(true, true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => new TrayProtectionActions(ipc, confirmation).PauseAsync(10));
        Assert.Equal(0, ipc.Mutations);
        Assert.Equal(0, confirmation.Count);
    }

    /// <summary>Authenticated administrator remains mandatory even for a new timed control.</summary>
    [Fact]
    public void PauseCommandDoesNotExpandCallerAuthorization()
    {
        Assert.False(ServiceControlCommandAuthorization.IsAllowed(ServiceCommandType.PauseFileProtection, false));
        Assert.True(ServiceControlCommandAuthorization.IsAllowed(ServiceCommandType.PauseFileProtection, true));
    }

    /// <summary>Preserves window identity and native scanner chrome while the approved classic themes share Segoe UI.</summary>
    [Fact]
    public void RestoredVisualResourcesKeepExistingLayout()
    {
        var root = Root();
        foreach (var path in new[] { "src/AegisPC.App/MainWindow.xaml", "src/AegisPC.App/Views/ActiveScanWindow.xaml" })
        {
            var xml = XDocument.Load(Path.Combine(root, path));
            if (path.EndsWith("ActiveScanWindow.xaml", StringComparison.Ordinal))
                Assert.DoesNotContain(xml.Descendants(), element => element.Name.LocalName == "TitleBar.Header");
            else Assert.Contains(xml.Descendants(), element => element.Name.LocalName == "TitleBar.Header");
            Assert.Contains("Ultron Defender", (string?)xml.Root!.Attribute("Title"));
        }
        var typography = File.ReadAllText(Path.Combine(root, "src/AegisPC.App/Resources/Themes/Typography.xaml"));
        Assert.Contains("x:Key=\"FontSans\">Segoe UI</FontFamily>", typography);
        Assert.DoesNotContain("Value=\"Segoe UI, Inter, Arial\"", File.ReadAllText(Path.Combine(root, "src/AegisPC.App/Resources/Themes/SharedStyles.xaml")));
        var scanner = XDocument.Load(Path.Combine(root, "src/AegisPC.App/Views/ActiveScanWindow.xaml"));
        Assert.Equal("Window", scanner.Root!.Name.LocalName);
        Assert.Equal("Tarayıcı - Ultron Defender Total Security", (string?)scanner.Root.Attribute("Title"));
    }

    private static string Root()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "AegisPC.sln"))) directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root unavailable.");
    }

    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = new(2026, 10, 8, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class PauseFixture
    {
        internal ProtectionPauseState? State;
        internal bool Enabled = true, FailSave, FailStop, FailEnable;
        internal int FailSaveNumber, SaveCount;
        internal readonly List<string> Events = new();
        internal readonly Clock Clock = new();
        internal readonly TimedFileProtectionPause Controller;
        internal PauseFixture() => Controller = new(() => State, state =>
        {
            if (FailSave || ++SaveCount == FailSaveNumber) throw new IOException("Injected state persistence failure.");
            State = state; Events.Add(state == null ? "save-clear" : "save-pause"); return Task.CompletedTask;
        }, enabled =>
        {
            if (enabled && FailEnable) throw new IOException("Injected enable failure.");
            Enabled = enabled; Events.Add(enabled ? "enable" : "disable");
            if (!enabled && FailStop) throw new IOException("Injected partial stop failure.");
            return Task.CompletedTask;
        }, () => Enabled, Clock);
    }
    private sealed class Confirmation(params bool[] choices) : IProtectionDisableConfirmation
    {
        internal int Count;
        public Task<bool> ConfirmAsync(string title, string message) => Task.FromResult(choices[Count++]);
    }
    private sealed class FakeIpc : IServiceIpcClient
    {
        public bool IsConnected { get; set; } = true;
        internal bool Supported = true;
        internal int Mutations;
        private ProtectionPauseState? _pause;
        public event Action<ThreatNotification>? ThreatDetected { add { } remove { } }
        public event Action<ProtectionStatus>? StatusChanged { add { } remove { } }
        public Task ConnectAsync() => Task.CompletedTask;
        public Task SendCommandAsync(ServiceCommand command)
        {
            Mutations++;
            if (command.CommandType == ServiceCommandType.PauseFileProtection)
            {
                using var payload = JsonDocument.Parse(command.Payload!);
                bool restart = payload.RootElement.GetProperty("ResumeOnServiceStart").GetBoolean();
                _pause = new() { ResumeOnServiceStart = restart, ResumeAtUtc = restart ? null : DateTime.UtcNow.AddMinutes(payload.RootElement.GetProperty("Minutes").GetInt32()) };
            }
            return Task.CompletedTask;
        }
        public Task<ProtectionStatus> GetStatusAsync() => Task.FromResult(new ProtectionStatus
        {
            IsServiceRunning = true, SupportsTimedFileProtectionPause = Supported,
            IsRealTimeEnabled = _pause == null, FileProtectionPause = _pause,
            ProtectionLevel = "inert-test", RequestId = Guid.NewGuid(),
            Health = new() { CapturedAtUtc = DateTime.UtcNow, State = ProtectionHealthState.Healthy }
        });
        public void Dispose() { }
    }
}
