using Ultron.PortableInspection;
using Xunit;

namespace Ultron.Linux.Tests;

/// <summary>Verifies pause state never blocks asynchronous cancellation or invents progress.</summary>
public sealed class ScanControlTests
{
    /// <summary>Verifies a paused waiter does not advance until explicit resume.</summary>
    [Fact]
    public async Task PauseRequiresResume()
    {
        var control = new ScanControl(); control.Pause();
        var waiting = control.WaitAsync(CancellationToken.None);
        Assert.False(waiting.IsCompleted);
        control.Resume();
        await waiting.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(control.IsPaused);
    }

    /// <summary>Verifies cancellation releases paused work through cancellation rather than a false completion.</summary>
    [Fact]
    public async Task PausedWorkCanBeCancelled()
    {
        var control = new ScanControl(); control.Pause();
        using var cancellation = new CancellationTokenSource();
        var waiting = control.WaitAsync(cancellation.Token);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.True(control.IsPaused);
    }
}
