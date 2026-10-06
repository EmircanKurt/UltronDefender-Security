using System.Collections;
using System.IO;
using System.Reflection;
using AegisPC.Infrastructure.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Delegate lifecycle fixtures only: no ETW session, live process, kernel driver or installed settings.</summary>
public sealed class ProtectionCommandLifecycleReviewTests
{
    [Fact]
    public void Disable_StopsEveryListenerEvenWhenAnEarlierStopThrows()
    {
        var stopped = new List<int>();
        var lifecycle = Create(Component(() => { }, () => stopped.Add(1), () => false),
            Component(() => { }, () => { stopped.Add(2); throw new IOException("fixture"); }, () => true),
            Component(() => { }, () => stopped.Add(3), () => false));
        var error = Assert.Throws<TargetInvocationException>(() => Invoke(lifecycle, "Disable"));
        Assert.IsType<AggregateException>(error.InnerException);
        Assert.Equal(new[] { 3, 2, 1 }, stopped);
        Assert.False(Healthy(lifecycle));
    }

    [Fact]
    public void EnableFailure_RollsBackOnlyNewListenersAndDoesNotStopExistingProtection()
    {
        var existingStopped = false;
        var freshActive = false;
        var lifecycle = Create(Component(() => throw new InvalidOperationException("already active"), () => existingStopped = true, () => true),
            Component(() => freshActive = true, () => freshActive = false, () => freshActive),
            Component(() => throw new IOException("fixture failure"), () => { }, () => false));
        Assert.Throws<TargetInvocationException>(() => Invoke(lifecycle, "Enable"));
        Assert.False(existingStopped);
        Assert.False(freshActive);
        Assert.False(Healthy(lifecycle));
    }

    [Fact]
    public void Enable_DoesNotClaimSuccessWhenRequiredListenerSilentlyFails()
    {
        var lifecycle = Create(Component(() => { }, () => { }, () => false));
        Assert.Throws<TargetInvocationException>(() => Invoke(lifecycle, "Enable"));
        Assert.False(Healthy(lifecycle));
    }

    [Fact]
    public void MissingKernelDriver_DoesNotPreventSupplementalUserModeActivation()
    {
        var requiredActive = false;
        var lifecycle = Create(Component(() => requiredActive = true, () => requiredActive = false, () => requiredActive),
            Component(() => { }, () => { }, () => false, requireActivation: false));
        Invoke(lifecycle, "Enable");
        Assert.True(Healthy(lifecycle));
        Invoke(lifecycle, "Disable");
        Assert.False(requiredActive);
    }

    [Fact]
    public void InactiveOptionalTelemetry_PreservesRequiredProtectionAndReportsPartialHealth()
    {
        var filesActive = false;
        var backgroundActive = false;
        var lifecycle = Create(Component(() => filesActive = true, () => filesActive = false, () => filesActive),
            Component(() => backgroundActive = true, () => backgroundActive = false, () => backgroundActive),
            Component(() => { }, () => { }, () => false, requireActivation: false, observeForHealth: true));

        Invoke(lifecycle, "Enable");

        Assert.True(filesActive);
        Assert.True(backgroundActive);
        Assert.False(Healthy(lifecycle));
    }

    [Fact]
    public void ThrowingOptionalTelemetry_DoesNotRollBackOrPreventRequiredProtection()
    {
        var filesActive = false;
        var backgroundActive = false;
        var lifecycle = Create(Component(() => filesActive = true, () => filesActive = false, () => filesActive),
            Component(() => throw new IOException("optional telemetry fixture failure"), () => { }, () => false,
                requireActivation: false, observeForHealth: true),
            Component(() => backgroundActive = true, () => backgroundActive = false, () => backgroundActive));

        Invoke(lifecycle, "Enable");

        Assert.True(filesActive);
        Assert.True(backgroundActive);
        Assert.False(Healthy(lifecycle));
    }

    [Fact]
    public void OptionalTelemetryCleanupFailure_DoesNotClaimHealthOrStopRequiredProtection()
    {
        var filesActive = false;
        var telemetryActive = false;
        var lifecycle = Create(Component(() => filesActive = true, () => filesActive = false, () => filesActive),
            Component(() => { telemetryActive = true; throw new IOException("partial start fixture failure"); },
                () => throw new IOException("optional cleanup fixture failure"), () => telemetryActive,
                requireActivation: false, observeForHealth: true));

        Invoke(lifecycle, "Enable");

        Assert.True(filesActive);
        Assert.True(telemetryActive);
        Assert.False(Healthy(lifecycle));
    }

    [Fact]
    public async Task EnableFailure_DoesNotChangeOrPersistDesiredMachineSetting()
    {
        var settingsPath = Path.Combine(Path.GetTempPath(), "AegisLifecycle_" + Guid.NewGuid().ToString("N"), "settings.json");
        var settings = new SettingsService(settingsPath);
        settings.Current.IsFileProtectionEnabled = false;
        var lifecycle = Create(Component(() => throw new IOException("fixture failure"), () => { }, () => false));
        var task = (Task)Invoke(lifecycle, "SetEnabledAsync", settings, true)!;
        await Assert.ThrowsAsync<IOException>(() => task);
        Assert.False(settings.Current.IsFileProtectionEnabled);
        Assert.False(File.Exists(settingsPath));
    }

    private static object Component(Action start, Action stop, Func<bool> isActive, bool requireActivation = true,
        bool? observeForHealth = null)
    {
        var type = typeof(AegisPC.Service.IPC.NamedPipeServer).Assembly.GetType("AegisPC.Service.IPC.ProtectionCommandComponent")!;
        return Activator.CreateInstance(type, start, stop, isActive, requireActivation, observeForHealth)!;
    }

    private static object Create(params object[] components)
    {
        var assembly = typeof(AegisPC.Service.IPC.NamedPipeServer).Assembly;
        var componentType = assembly.GetType("AegisPC.Service.IPC.ProtectionCommandComponent")!;
        var list = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(componentType))!;
        foreach (var component in components) list.Add(component);
        var lifecycleType = assembly.GetType("AegisPC.Service.IPC.ProtectionCommandLifecycle")!;
        return Activator.CreateInstance(lifecycleType, list, NullLogger.Instance)!;
    }

    private static object? Invoke(object lifecycle, string method, params object[] args) =>
        lifecycle.GetType().GetMethod(method)!.Invoke(lifecycle, args);

    private static bool Healthy(object lifecycle) => (bool)lifecycle.GetType().GetProperty("IsHealthy")!.GetValue(lifecycle)!;
}
