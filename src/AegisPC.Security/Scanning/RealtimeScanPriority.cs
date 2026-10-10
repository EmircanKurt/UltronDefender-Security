namespace AegisPC.Security.Scanning;

/// <summary>Lets bounded real-time arrivals defer new bulk work in this process; never preempts an active file or implies cross-service quotas.</summary>
internal static class RealtimeScanPriority
{
    private static readonly object Sync = new();
    private static int _active;
    private static TaskCompletionSource _idle = Completed();

    internal static IDisposable Enter()
    {
        lock (Sync)
        {
            if (_active++ == 0) _idle = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        return new Lease();
    }

    internal static async Task WaitAsync(CancellationToken token)
    {
        Task idle;
        lock (Sync) idle = _idle.Task;
        // Age bulk admission so an uninterrupted RT storm cannot starve every scan.
        // This only grants permission to compete for the shared resource slot, not extra workers.
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(token);
        wait.CancelAfter(TimeSpan.FromMilliseconds(250));
        try { await idle.WaitAsync(wait.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
        token.ThrowIfCancellationRequested();
    }

    private static TaskCompletionSource Completed()
    { var signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); signal.SetResult(); return signal; }

    private sealed class Lease : IDisposable
    {
        private int _disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            lock (Sync) if (--_active == 0) _idle.TrySetResult();
        }
    }
}
