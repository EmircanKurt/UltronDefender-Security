using System.Reflection;
using AegisPC.Security.Detection.YaraEngine;
using Xunit;

namespace Ultron.Linux.Tests;

/// <summary>Verifies the actual shared rule engine remains in memory after its isolated default-only directory is removed.</summary>
public sealed class ManagedRuleSnapshotTests
{
    /// <summary>Checks default-only loading and immediate temporary-directory cleanup on an actual Linux runner.</summary>
    [LinuxFact]
    public async Task DefaultOnlySnapshotDoesNotRetainPersistentRuleFolder()
    {
        var type = typeof(Ultron.Linux.App.MainWindow).Assembly.GetType("Ultron.Linux.App.DefaultManagedRules", throwOnError: true)!;
        var create = type.GetMethod("Create", BindingFlags.NonPublic | BindingFlags.Static)!;
        var engine = Assert.IsAssignableFrom<IYaraEngine>(create.Invoke(null, null));
        Assert.Equal(3, engine.LoadedRuleCount);
        Assert.False(Directory.Exists(engine.RulesDirectory));
        Assert.Empty(await engine.ScanBufferAsync("Ordinary inert Linux rule snapshot fixture."u8.ToArray()));
    }
}
