namespace Ultron.PortableInspection;

/// <summary>Pauses admission between bounded operations; cancellation remains effective while paused.</summary>
public sealed class ScanControl
{
    private readonly object _gate = new();
    private TaskCompletionSource? _resume;

    /// <summary>Returns whether new file and archive work is currently paused.</summary>
    public bool IsPaused { get { lock (_gate) return _resume != null; } }

    /// <summary>Suspends admission after any currently running bounded operation finishes.</summary>
    public void Pause() { lock (_gate) _resume ??= new(TaskCreationOptions.RunContinuationsAsynchronously); }

    /// <summary>Resumes admission and releases all waiting callers.</summary>
    public void Resume()
    {
        TaskCompletionSource? resume;
        lock (_gate) { resume = _resume; _resume = null; }
        resume?.TrySetResult();
    }

    /// <summary>Waits asynchronously for admission; cancellation propagates instead of resuming work.</summary>
    public Task WaitAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        lock (_gate) return _resume?.Task.WaitAsync(ct) ?? Task.CompletedTask;
    }
}
