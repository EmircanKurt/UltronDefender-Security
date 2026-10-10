using System.Collections;
using System.IO;
using System.Reflection;
using AegisPC.Contracts.Devices;
using AegisPC.Core.Models.Devices;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.RealTime;
using AegisPC.Service.IPC;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert device/lifecycle fixtures; no OS device monitor, service or machine settings are started.</summary>
public sealed class ProtectionLifecycleDeviceTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisDeviceLifecycle_" + Guid.NewGuid().ToString("N"));

    /// <summary>A device stop failure cannot skip subsequent file/telemetry component stops or persist success.</summary>
    [Fact]
    public async Task DeviceStopFailure_StillStopsAllComponentsAndPreservesDesiredSetting()
    {
        var stopped = new List<int>();
        var monitor = new FixtureMonitor(() => { stopped.Add(0); throw new IOException("fixture device stop failure"); });
        var lifecycle = CreateLifecycle(monitor, Component(() => stopped.Add(1)), Component(() => stopped.Add(2)));
        var settings = Settings();

        var exception = await Assert.ThrowsAsync<AggregateException>(() => SetEnabled(lifecycle, settings, false));

        Assert.Single(exception.Flatten().InnerExceptions);
        Assert.Equal(new[] { 0, 2, 1 }, stopped);
        Assert.True(settings.Current.IsFileProtectionEnabled);
        Assert.False(File.Exists(Path.Combine(_root, "settings.json")));
        Assert.False(Healthy(lifecycle));
    }

    /// <summary>Combined device and component failures are aggregated after every remaining stop is attempted.</summary>
    [Fact]
    public async Task DeviceAndComponentFailures_AreAggregatedAfterRemainingStops()
    {
        var stopped = new List<int>();
        var monitor = new FixtureMonitor(() => { stopped.Add(0); throw new IOException("fixture device failure"); });
        var lifecycle = CreateLifecycle(monitor, Component(() => stopped.Add(1)),
            Component(() => { stopped.Add(2); throw new InvalidOperationException("fixture listener failure"); }));

        var exception = await Assert.ThrowsAsync<AggregateException>(() => SetEnabled(lifecycle, Settings(), false));

        Assert.Equal(2, exception.Flatten().InnerExceptions.Count);
        Assert.Equal(new[] { 0, 2, 1 }, stopped);
        Assert.False(Healthy(lifecycle));
    }

    /// <summary>A silently active device monitor is a failed stop, without preventing other components from stopping.</summary>
    [Fact]
    public async Task DeviceStopNoOp_IsNotReportedAsCompleted()
    {
        int componentStops = 0;
        var monitor = new FixtureMonitor(() => { }) { RemainActive = true };
        var lifecycle = CreateLifecycle(monitor, Component(() => componentStops++));

        var exception = await Assert.ThrowsAsync<AggregateException>(() => SetEnabled(lifecycle, Settings(), false));

        Assert.IsType<InvalidOperationException>(Assert.Single(exception.Flatten().InnerExceptions));
        Assert.Equal(1, componentStops);
        Assert.False(Healthy(lifecycle));
    }

    /// <summary>Only a fully completed disable persists the desired state to the isolated fixture settings file.</summary>
    [Fact]
    public async Task CompletedDisable_PersistsOnlyFixtureSettings()
    {
        int componentStops = 0;
        var lifecycle = CreateLifecycle(new FixtureMonitor(() => { }), Component(() => componentStops++));
        var settings = Settings();

        await SetEnabled(lifecycle, settings, false);

        Assert.Equal(1, componentStops);
        Assert.False(settings.Current.IsFileProtectionEnabled);
        Assert.True(File.Exists(Path.Combine(_root, "settings.json")));
    }

    /// <summary>Volume enumeration success with partial HID metadata cannot clear a previously observed keyboard.</summary>
    [Fact]
    public void CompletePartialCompleteInventory_PreservesFunctionBaseline()
    {
        using var engine = new RealTimeProtectionEngine(new RealTimeEventIngestor(8), new FixtureStable(), new FixtureVerdict(), new FixturePolicy());
        using var server = new NamedPipeServer(NullLogger<NamedPipeServer>.Instance,
            DispatchProxy.Create<IBackgroundProtectionService, InertConstructorProxy>(), engine,
            DispatchProxy.Create<IRansomwareProtectionEngine, InertConstructorProxy>(), Settings());
        var keyboard = new DeviceMetadata { InstanceId = "fixture-keyboard", UsbAssociation = UsbAssociation.Usb,
            Functions = DeviceFunction.Hid | DeviceFunction.Keyboard, MetadataComplete = true };
        var good = new DeviceInventorySnapshot([keyboard], [], true, presenceComplete: true);

        Publish(server, good);
        var baseline = Baseline(server);
        Assert.Equal(keyboard.Functions, baseline[keyboard.InstanceId]);
        Publish(server, new DeviceInventorySnapshot([], [], false, "HID query failed", presenceComplete: true));
        Assert.Equal(keyboard.Functions, Assert.Single(baseline).Value);
        Publish(server, good);
        Assert.Equal(keyboard.Functions, Assert.Single(baseline).Value);
    }

    /// <summary>An incomplete first capture cannot become the baseline for later new-keyboard classification.</summary>
    [Fact]
    public void PartialInitialInventory_DoesNotEstablishFunctionBaseline()
    {
        using var engine = new RealTimeProtectionEngine(new RealTimeEventIngestor(8), new FixtureStable(), new FixtureVerdict(), new FixturePolicy());
        using var server = new NamedPipeServer(NullLogger<NamedPipeServer>.Instance,
            DispatchProxy.Create<IBackgroundProtectionService, InertConstructorProxy>(), engine,
            DispatchProxy.Create<IRansomwareProtectionEngine, InertConstructorProxy>(), Settings());

        Publish(server, new DeviceInventorySnapshot([], [], false, "HID metadata unavailable", presenceComplete: true));

        Assert.False((bool)typeof(NamedPipeServer).GetField("_deviceBaseline", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(server)!);
        Assert.Empty(Baseline(server));
    }

    private SettingsService Settings()
    {
        var settings = new SettingsService(Path.Combine(_root, "settings.json"));
        settings.Current.IsFileProtectionEnabled = true;
        return settings;
    }

    private static object Component(Action stop)
    {
        var type = typeof(NamedPipeServer).Assembly.GetType("AegisPC.Service.IPC.ProtectionCommandComponent")!;
        return Activator.CreateInstance(type, (Action)(() => { }), stop, (Func<bool>)(() => false), true, null)!;
    }

    private static object CreateLifecycle(IDeviceInventoryMonitor monitor, params object[] components)
    {
        var assembly = typeof(NamedPipeServer).Assembly;
        var componentType = assembly.GetType("AegisPC.Service.IPC.ProtectionCommandComponent")!;
        var list = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(componentType))!;
        foreach (var component in components) list.Add(component);
        var type = assembly.GetType("AegisPC.Service.IPC.ProtectionCommandLifecycle")!;
        return Activator.CreateInstance(type, list, NullLogger.Instance, monitor)!;
    }

    private static Task SetEnabled(object lifecycle, SettingsService settings, bool enabled) =>
        (Task)lifecycle.GetType().GetMethod("SetEnabledAsync")!.Invoke(lifecycle, new object[] { settings, enabled })!;
    private static bool Healthy(object lifecycle) => (bool)lifecycle.GetType().GetProperty("IsHealthy")!.GetValue(lifecycle)!;
    private static void Publish(NamedPipeServer server, DeviceInventorySnapshot snapshot) =>
        typeof(NamedPipeServer).GetMethod("OnDeviceSnapshotChanged", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(server, new object[] { snapshot });
    private static Dictionary<string, DeviceFunction> Baseline(NamedPipeServer server) =>
        (Dictionary<string, DeviceFunction>)typeof(NamedPipeServer).GetField("_observedFunctions", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(server)!;

    /// <summary>Removes only the settings fixture directory created by this test instance, if persistence created it.</summary>
    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true); }

    private sealed class FixtureMonitor(Action stop) : IDeviceInventoryMonitor
    {
        internal bool RemainActive { get; init; }
        /// <inheritdoc />
        public bool IsRunning { get; private set; } = true;
        /// <inheritdoc />
        public DeviceInventorySnapshot CurrentSnapshot { get; } = new([], [], true);
        /// <inheritdoc />
        public event Action<DeviceInventorySnapshot>? SnapshotChanged { add { } remove { } }
        /// <inheritdoc />
        public Task StartAsync(CancellationToken cancellationToken = default) { IsRunning = true; return Task.CompletedTask; }
        /// <inheritdoc />
        public Task StopAsync(CancellationToken cancellationToken = default)
        { stop(); IsRunning = RemainActive; return Task.CompletedTask; }
    }

    private sealed class FixtureStable : IRealTimeStabilityChecker
    {
        /// <inheritdoc />
        public Task<bool> WaitForFileStabilityAsync(string filePath, CancellationToken ct) => Task.FromResult(true);
    }

    private sealed class FixtureVerdict : IRealTimeVerdictProcessor
    {
        /// <inheritdoc />
        public Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default) =>
            throw new InvalidOperationException("No engine scan is started by device baseline fixtures.");
        /// <inheritdoc />
        public void CleanupCache() { }
    }

    private sealed class FixturePolicy : IRealTimePolicyEnforcer
    {
        /// <inheritdoc />
        public event Action<AegisPC.Core.Models.SecurityFinding>? OnThreatDetected { add { } remove { } }
        /// <inheritdoc />
        public event Action<AegisPC.Core.Models.SecurityIncident>? OnIncidentCreated { add { } remove { } }
        /// <inheritdoc />
        public event Action<string, string, string>? OnNotificationRaised { add { } remove { } }
        /// <inheritdoc />
        public Task EnforceWarningAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct) => Task.CompletedTask;
        /// <inheritdoc />
        public Task EnforceQuarantineAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct) => Task.CompletedTask;
    }

    /// <summary>Constructor-only event/delegate stand-in; no OS APIs or protection listeners are executed.</summary>
    public class InertConstructorProxy : DispatchProxy
    {
        /// <summary>Returns defaults for constructor subscriptions without implementing any protection operation.</summary>
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
            targetMethod?.ReturnType == typeof(bool) ? false : null;
    }
}
