using System.IO;
using AegisPC.App.Services;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Fresh service preference propagation through fake IPC and isolated settings files; no live service or local engine is operated.</summary>
public sealed class UiAiPreferenceSyncTests
{
    /// <summary>Service observations apply and survive restart even when no SettingsViewModel exists.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FreshObservation_PersistsIndependentOfSettingsPage(bool enabled)
    {
        string folder = FixtureFolder();
        try
        {
            var settings = new SettingsService(Path.Combine(folder, "settings.json"));
            settings.Current.IsUltronAiEnabled = !enabled;
            await settings.SaveAsync();
            var ipc = new FixtureIpc();
            await using var sync = new UltronAiServicePreferenceSync(ipc, settings);
            long before = DetectionPolicyRevision.Current;
            ipc.Publish(Status(enabled));
            await sync.SynchronizeAsync();
            Assert.Equal(enabled, settings.Current.IsUltronAiEnabled);
            Assert.True(DetectionPolicyRevision.Current > before);
            var restarted = new SettingsService(Path.Combine(folder, "settings.json"));
            await restarted.LoadAsync();
            Assert.Equal(enabled, restarted.Current.IsUltronAiEnabled);
            Assert.Null(sync.LastSynchronizationError);
            Assert.Equal(0, ipc.Controls);
            Assert.Equal(0, ipc.Connects);
        }
        finally { Directory.Delete(folder, true); }
    }

    /// <summary>Legacy, stale, future, incompatible and disconnected observations cannot mutate runtime settings or produce a settings file.</summary>
    [Theory]
    [InlineData("legacy")]
    [InlineData("missing-health")]
    [InlineData("stale")]
    [InlineData("future")]
    [InlineData("incompatible")]
    [InlineData("disconnected")]
    [InlineData("not-running")]
    public async Task UnverifiedObservation_DoesNotApplyOrSave(string condition)
    {
        string folder = FixtureFolder();
        try
        {
            string path = Path.Combine(folder, "settings.json");
            var settings = new SettingsService(path);
            var ipc = new FixtureIpc();
            await using var sync = new UltronAiServicePreferenceSync(ipc, settings);
            var status = Status(false);
            if (condition == "legacy") status.IsUltronAiEnabled = null;
            if (condition == "missing-health") status.Health = null;
            if (condition == "stale") status.Health = new ProtectionHealthSnapshot { CapturedAtUtc = DateTime.UtcNow.AddMinutes(-1) };
            if (condition == "future") status.Health = new ProtectionHealthSnapshot { CapturedAtUtc = DateTime.UtcNow.AddMinutes(1) };
            if (condition == "incompatible") status.Health = new ProtectionHealthSnapshot { CapturedAtUtc = DateTime.UtcNow, ProtocolVersion = 99 };
            if (condition == "disconnected") ipc.IsConnected = false;
            if (condition == "not-running") status.IsServiceRunning = false;
            ipc.Publish(status);
            await sync.SynchronizeAsync();
            Assert.True(settings.Current.IsUltronAiEnabled);
            Assert.False(File.Exists(path));
            Assert.Equal(0, ipc.Controls);
        }
        finally { Directory.Delete(folder, true); }
    }

    /// <summary>An earlier subscriber's runtime update does not suppress necessary persistence of the service-owned preference.</summary>
    [Fact]
    public async Task RuntimeAlreadyMirrored_StillPersistsChangedObservation()
    {
        string folder = FixtureFolder();
        try
        {
            string path = Path.Combine(folder, "settings.json");
            var settings = new SettingsService(path);
            var ipc = new FixtureIpc();
            await using var sync = new UltronAiServicePreferenceSync(ipc, settings);
            settings.Current.IsUltronAiEnabled = false; // Simulates another UI subscriber to the same legitimate event.
            ipc.Publish(Status(false));
            await sync.SynchronizeAsync();
            var restarted = new SettingsService(path);
            await restarted.LoadAsync();
            Assert.False(restarted.Current.IsUltronAiEnabled);
        }
        finally { Directory.Delete(folder, true); }
    }

    /// <summary>One latest-state slot converges to the final observed preference during a benign burst.</summary>
    [Fact]
    public async Task ObservationBurst_ConvergesToLatestState()
    {
        string folder = FixtureFolder();
        try
        {
            string path = Path.Combine(folder, "settings.json");
            var settings = new SettingsService(path);
            var ipc = new FixtureIpc();
            await using var sync = new UltronAiServicePreferenceSync(ipc, settings);
            for (int index = 0; index < 1000; index++) ipc.Publish(Status(index % 2 == 0));
            await sync.SynchronizeAsync();
            Assert.False(settings.Current.IsUltronAiEnabled);
            var restarted = new SettingsService(path);
            await restarted.LoadAsync();
            Assert.False(restarted.Current.IsUltronAiEnabled);
            Assert.Equal(0, ipc.Controls);
        }
        finally { Directory.Delete(folder, true); }
    }

    /// <summary>Mutating the source event after publication cannot rewrite the copied pending preference.</summary>
    [Fact]
    public async Task EventPayloadMutation_CannotChangeCopiedObservation()
    {
        string folder = FixtureFolder();
        try
        {
            var settings = new SettingsService(Path.Combine(folder, "settings.json"));
            var ipc = new FixtureIpc();
            await using var sync = new UltronAiServicePreferenceSync(ipc, settings);
            var status = Status(false);
            ipc.Publish(status);
            status.IsUltronAiEnabled = true;
            await sync.SynchronizeAsync();
            Assert.False(settings.Current.IsUltronAiEnabled);
        }
        finally { Directory.Delete(folder, true); }
    }

    /// <summary>A failed disk commit stays visible and a later fresh identical heartbeat retries rather than losing the preference.</summary>
    [Fact]
    public async Task PersistenceFailure_IsObservedAndRetriedOnFreshHeartbeat()
    {
        string folder = FixtureFolder();
        try
        {
            string path = Path.Combine(folder, "settings.json");
            Directory.CreateDirectory(path); // Only a private fixture destination is intentionally obstructed.
            var settings = new SettingsService(path);
            var ipc = new FixtureIpc();
            await using var sync = new UltronAiServicePreferenceSync(ipc, settings);
            ipc.Publish(Status(false));
            await sync.SynchronizeAsync();
            Assert.False(settings.Current.IsUltronAiEnabled);
            string error = Assert.IsType<string>(sync.LastSynchronizationError);
            Assert.DoesNotContain(path, error);
            Directory.Delete(path); // The fixture's empty obstruction, not existing user data.
            ipc.Publish(Status(false));
            await sync.SynchronizeAsync();
            Assert.Null(sync.LastSynchronizationError);
            var restarted = new SettingsService(path);
            await restarted.LoadAsync();
            Assert.False(restarted.Current.IsUltronAiEnabled);
        }
        finally { Directory.Delete(folder, true); }
    }

    /// <summary>Disposal removes subscriptions; later fake service events cannot mutate preferences or start work.</summary>
    [Fact]
    public async Task Dispose_UnsubscribesAndRejectsLaterEvents()
    {
        string folder = FixtureFolder();
        try
        {
            string path = Path.Combine(folder, "settings.json");
            var settings = new SettingsService(path);
            var ipc = new FixtureIpc();
            var sync = new UltronAiServicePreferenceSync(ipc, settings);
            Assert.Equal(1, ipc.Subscribers);
            await sync.DisposeAsync();
            sync.Dispose();
            Assert.Equal(0, ipc.Subscribers);
            ipc.Publish(Status(false));
            Assert.True(settings.Current.IsUltronAiEnabled);
            Assert.False(File.Exists(path));
            Assert.Equal(0, ipc.Controls);
        }
        finally { Directory.Delete(folder, true); }
    }

    private static string FixtureFolder()
    {
        string folder = Path.Combine(Path.GetTempPath(), "UltronUiAiSyncFixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        return folder;
    }

    private static ProtectionStatus Status(bool enabled) => new()
    {
        IsServiceRunning = true, IsUltronAiEnabled = enabled, ProtectionLevel = "Inert preference fixture",
        Health = new ProtectionHealthSnapshot { CapturedAtUtc = DateTime.UtcNow, State = ProtectionHealthState.Degraded }
    };

    private sealed class FixtureIpc : IServiceIpcClient
    {
        private Action<ProtectionStatus>? _statusChanged;
        internal int Subscribers => _statusChanged?.GetInvocationList().Length ?? 0;
        internal int Controls;
        internal int Connects;
        /// <inheritdoc />
        public bool IsConnected { get; set; } = true;
        /// <inheritdoc />
        public event Action<ProtectionStatus>? StatusChanged { add => _statusChanged += value; remove => _statusChanged -= value; }
        /// <inheritdoc />
        public event Action<ThreatNotification>? ThreatDetected { add { } remove { } }
        /// <inheritdoc />
        public Task ConnectAsync() { Connects++; throw new InvalidOperationException("Sync must not initiate a service connection."); }
        /// <inheritdoc />
        public Task SendCommandAsync(ServiceCommand command) { Controls++; throw new InvalidOperationException("Sync must not send protection controls."); }
        /// <inheritdoc />
        public Task<ProtectionStatus> GetStatusAsync() => throw new InvalidOperationException("Sync only observes the existing authenticated event stream.");
        /// <inheritdoc />
        public void Dispose() { }
        internal void Publish(ProtectionStatus status) => _statusChanged?.Invoke(status);
    }
}
