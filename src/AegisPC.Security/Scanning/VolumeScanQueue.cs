using System.Threading.Channels;
using System.Diagnostics;

namespace AegisPC.Security.Scanning;

/// <summary>Bounded round-robin admission prevents busy seek-limited volumes from owning every analysis worker.</summary>
internal sealed class VolumeScanQueue<T>(int capacity, Func<T, string> volumeKey, Func<string, int> volumeLimit)
{
    private sealed class Volume(string key)
    {
        internal readonly Queue<(T Item, long QueuedAt)> Items = new();
        internal readonly SemaphoreSlim Space = new(32, 32);
        internal int Active;
        internal readonly string Key = key;
    }

    private readonly object _sync = new();
    private readonly SemaphoreSlim _space = new(capacity, capacity);
    private readonly Dictionary<string, Volume> _volumes = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Volume> _order = new();
    private TaskCompletionSource _changed = NewSignal();
    private int _cursor;
    private bool _complete;
    private Exception? _failure;

    internal async Task WriteAsync(T item, CancellationToken token)
    {
        long queuedAt = Stopwatch.GetTimestamp();
        string key = volumeKey(item);
        Volume volume;
        lock (_sync)
        {
            if (!_volumes.TryGetValue(key, out volume!))
            {
                if (_volumes.Count >= 128) throw new InvalidOperationException("Scan volume identity budget exceeded.");
                volume = new Volume(key);
                _volumes.Add(key, volume);
                _order.Add(volume);
            }
        }
        await volume.Space.WaitAsync(token);
        bool totalAcquired = false, written = false;
        try
        {
            await _space.WaitAsync(token);
            totalAcquired = true;
            lock (_sync)
            {
                if (_complete) throw new ChannelClosedException(_failure);
                volume.Items.Enqueue((item, queuedAt));
                written = true;
                Pulse();
            }
        }
        finally
        {
            if (!written)
            {
                volume.Space.Release();
                if (totalAcquired) _space.Release();
            }
        }
    }

    internal async Task<Lease?> ReadAsync(CancellationToken token)
    {
        while (true)
        {
            token.ThrowIfCancellationRequested();
            Volume[] snapshot;
            lock (_sync) snapshot = _order.ToArray();
            // The callback may query storage or refresh policy. Never run it under the queue lock.
            var limits = snapshot.ToDictionary(v => v.Key, v => Math.Max(1, volumeLimit(v.Key)), StringComparer.OrdinalIgnoreCase);
            Task changed;
            lock (_sync)
            {
                for (int i = 0; i < _order.Count; i++)
                {
                    int index = (_cursor + i) % _order.Count;
                    var volume = _order[index];
                    int limit = limits.GetValueOrDefault(volume.Key, 1);
                    if (volume.Active >= limit || !volume.Items.TryDequeue(out var item)) continue;
                    _cursor = (index + 1) % _order.Count;
                    volume.Active++;
                    volume.Space.Release();
                    _space.Release();
                    return new Lease(item.Item, item.QueuedAt, () => { lock (_sync) { volume.Active--; Pulse(); } });
                }
                if (_complete && _order.All(v => v.Items.Count == 0))
                {
                    if (_failure != null) throw new ChannelClosedException(_failure);
                    return null;
                }
                changed = _changed.Task;
            }
            await changed.WaitAsync(token);
        }
    }

    internal void Complete(Exception? failure = null)
    { lock (_sync) { _complete = true; _failure ??= failure; Pulse(); } }

    private void Pulse() { _changed.TrySetResult(); _changed = NewSignal(); }
    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal sealed class Lease(T item, long queuedAt, Action release) : IDisposable
    {
        private Action? _release = release;
        internal T Item => item;
        internal long QueuedAt => queuedAt;
        public void Dispose() => Interlocked.Exchange(ref _release, null)?.Invoke();
    }
}
