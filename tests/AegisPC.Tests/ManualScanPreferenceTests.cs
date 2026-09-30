using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Infrastructure.Configuration;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Exercises persisted manual scan preferences with isolated settings files and no live protection services.</summary>
public sealed class ManualScanPreferenceTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(),
        "AegisManualScanPreference_" + Guid.NewGuid().ToString("N"));

    private string SettingsPath => Path.Combine(_directory, "settings.json");

    /// <summary>Creates a fresh temporary settings location for each migration scenario.</summary>
    public ManualScanPreferenceTests() => Directory.CreateDirectory(_directory);

    /// <summary>Removes only this test instance's temporary settings directory.</summary>
    public void Dispose() => Directory.Delete(_directory, recursive: true);

    /// <summary>Ensures a legacy remembered manual choice is copied without altering scheduled scans.</summary>
    [Fact]
    public async Task LegacyRememberedMode_MigratesWithoutChangingScheduledProfile()
    {
        await File.WriteAllTextAsync(SettingsPath,
            "{\"RememberScanResourceMode\":true,\"ScanResourceMode\":5}");
        var settings = new SettingsService(SettingsPath);

        await settings.LoadAsync();

        Assert.Equal(ScanResourceMode.Maximum, settings.Current.ScanResourceMode);
        Assert.Equal(ScanResourceMode.Maximum, settings.Current.LastManualScanResourceMode);
        Assert.True(settings.Current.RememberScanResourceMode);
    }

    /// <summary>Ensures a scheduled mode change cannot replace a migrated manual choice.</summary>
    [Fact]
    public async Task MigratedManualPreference_RemainsSeparateAfterScheduledModeChanges()
    {
        await File.WriteAllTextAsync(SettingsPath,
            "{\"RememberScanResourceMode\":true,\"ScanResourceMode\":5}");
        var settings = new SettingsService(SettingsPath);
        await settings.LoadAsync();
        settings.Current.ScanResourceMode = ScanResourceMode.Low;
        await settings.SaveAsync();

        var reloaded = new SettingsService(SettingsPath);
        await reloaded.LoadAsync();

        Assert.Equal(ScanResourceMode.Low, reloaded.Current.ScanResourceMode);
        Assert.Equal(ScanResourceMode.Maximum, reloaded.Current.LastManualScanResourceMode);
    }

    /// <summary>Ensures non-remembered manual scans do not inherit a scheduled scan profile.</summary>
    [Fact]
    public async Task RememberDisabled_DoesNotDeriveManualPreferenceFromScheduledMode()
    {
        await File.WriteAllTextAsync(SettingsPath,
            "{\"RememberScanResourceMode\":false,\"ScanResourceMode\":5}");
        var settings = new SettingsService(SettingsPath);

        await settings.LoadAsync();

        Assert.Equal(ScanResourceMode.Maximum, settings.Current.ScanResourceMode);
        Assert.Null(settings.Current.LastManualScanResourceMode);
    }

    /// <summary>Ensures invalid persisted manual values are rejected before the UI reads them.</summary>
    [Fact]
    public async Task InvalidManualMode_IsNotLoadedAsAnUncheckedEnumValue()
    {
        await File.WriteAllTextAsync(SettingsPath,
            "{\"RememberScanResourceMode\":false,\"ScanResourceMode\":3,\"LastManualScanResourceMode\":999}");
        var settings = new SettingsService(SettingsPath);

        await settings.LoadAsync();

        Assert.Null(settings.Current.LastManualScanResourceMode);
        Assert.Equal(ScanResourceMode.Balanced, settings.Current.ScanResourceMode);
    }
}
