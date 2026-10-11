using System.Reflection;
using Xunit;

namespace Ultron.Linux.Tests;

/// <summary>Verifies the actual admission budget reserves attempted I/O before opening an unstable source.</summary>
public sealed class SourceByteBudgetTests
{
    /// <summary>Verifies failed attempts cannot recycle the fixed session byte budget or expand it through overflow.</summary>
    [Fact]
    public void AttemptedReadsConsumeBudgetBeforeSuccessfulCompletion()
    {
        var assembly = typeof(Ultron.PortableInspection.ManualScopeScanner).Assembly;
        var type = assembly.GetType("Ultron.PortableInspection.SourceByteBudget", throwOnError: true)!;
        object budget = Activator.CreateInstance(type, nonPublic: true)!;
        var reserve = type.GetMethod("TryReserve", BindingFlags.Instance | BindingFlags.NonPublic)!;
        for (int index = 0; index < 16; index++)
            Assert.True((bool)reserve.Invoke(budget, [16UL * 1024 * 1024])!);
        Assert.False((bool)reserve.Invoke(budget, [1UL])!);
        Assert.False((bool)reserve.Invoke(budget, [ulong.MaxValue])!);
    }
}
