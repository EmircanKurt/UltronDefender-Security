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

    internal static Task WaitAsync(CancellationToken token)
    { lock (Sync) return _idle.Task.WaitAsync(token); }

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
