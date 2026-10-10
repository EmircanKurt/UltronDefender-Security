using System.Diagnostics;
using System.Threading.Channels;

namespace AegisPC.BrowserSecurity.Browser;

/// <summary>Describes metadata-only changes; it never contains cookies, browsing history or a presumed writer process.</summary>
public sealed record BrowserMetadataChange
{
    /// <summary>Gets the authorized metadata root where the notification originated.</summary>
    public BrowserProfileRoot Root { get; init; } = new();
    /// <summary>Gets the changed metadata path, never its contents.</summary>
    public string MetadataPath { get; init; } = string.Empty;
    /// <summary>Gets the file-system event type; notification does not prove who wrote or read the file.</summary>
    public WatcherChangeTypes ChangeType { get; init; }
    /// <summary>Gets the local UTC observation time.</summary>
    public DateTimeOffset ObservedAtUtc { get; init; }
}

/// <summary>Reports metadata observer health without claiming pre-access browser or cookie protection.</summary>
public sealed record BrowserInventoryMonitorHealth
{
    /// <summary>Gets whether observers were explicitly started and are not disposed.</summary>
    public bool IsRunning { get; init; }
    /// <summary>Gets the number of requested distinct browser roots, including unavailable ones.</summary>
    public int RequestedRoots { get; init; }
    /// <summary>Gets the number of successfully attached metadata watchers.</summary>
    public int ActiveWatchers { get; init; }
    /// <summary>Gets the count of queue drops and watcher errors; it is not an exact count of all lost OS events.</summary>
    public long KnownLossCount { get; init; }
    /// <summary>Gets whether errors or unattached roots require a fresh bounded inventory and watcher reconciliation.</summary>
    public bool RequiresReconciliation { get; init; }
    /// <summary>Gets the last metadata event time, or null when none was observed.</summary>
    public DateTimeOffset? LastObservedAtUtc { get; init; }
}

/// <summary>Provides explicit, bounded metadata observation; ownership and service health integration remain with the caller.</summary>
public interface IBrowserInventoryMonitor : IDisposable
{
    /// <summary>Attaches observers to authorized roots once; absent or unsafe roots create visible coverage gaps.</summary>
    void Start(IReadOnlyList<BrowserProfileRoot> roots);
    /// <summary>Reads bounded metadata events until cancellation or disposal; no cookie data or writer attribution is provided.</summary>
    IAsyncEnumerable<BrowserMetadataChange> ReadChangesAsync(CancellationToken cancellationToken = default);
    /// <summary>Returns actual watcher and known-loss state, not whether browser data is safe.</summary>
    BrowserInventoryMonitorHealth GetHealth();
}

/// <summary>Watches only extension inventory metadata and queues notifications without opening profile secrets.</summary>
public sealed class BrowserInventoryMonitor : IBrowserInventoryMonitor
{
    private const int MaximumRoots = 16;
    private readonly object _gate = new();
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly Channel<BrowserMetadataChange> _changes = Channel.CreateBounded<BrowserMetadataChange>(
        new BoundedChannelOptions(128) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = false });
    private long _knownLossCount;
    private long _lastObservedTicks;
    private int _requestedRoots;
    private bool _started;
    private bool _disposed;

    /// <summary>Attaches watchers once without reading cookies or modifying any browser profile; invalid roots remain uncovered.</summary>
    public void Start(IReadOnlyList<BrowserProfileRoot> roots)
    {
        ArgumentNullException.ThrowIfNull(roots);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_started) throw new InvalidOperationException("Browser metadata monitor has already been started.");
            _started = true;
            _requestedRoots = roots.Count;
            foreach (var root in roots.Take(MaximumRoots).DistinctBy(item => (item.BrowserType, item.RootPath.ToUpperInvariant())))
                Attach(root);
        }
    }

    private void Attach(BrowserProfileRoot root)
    {
        FileSystemWatcher? watcher = null;
        try
        {
            if (string.IsNullOrWhiteSpace(root.RootPath) || !Directory.Exists(root.RootPath)
                || !BrowserMetadataReader.IsOrdinaryPath(root.RootPath)) return;
            watcher = new FileSystemWatcher(root.RootPath)
            {
                IncludeSubdirectories = true, Filter = "*", InternalBufferSize = 8192,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size
            };
            watcher.Created += (_, args) => Publish(root, args.FullPath, args.ChangeType);
            watcher.Changed += (_, args) => Publish(root, args.FullPath, args.ChangeType);
            watcher.Deleted += (_, args) => Publish(root, args.FullPath, args.ChangeType);
            watcher.Renamed += (_, args) =>
            {
                Publish(root, args.OldFullPath, args.ChangeType);
                Publish(root, args.FullPath, args.ChangeType);
            };
            watcher.Error += (_, args) =>
            {
                Interlocked.Increment(ref _knownLossCount);
                Trace.WriteLine($"Browser Defender metadata watcher failed: {args.GetException().GetType().Name}.");
            };
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            watcher?.Dispose();
            Interlocked.Increment(ref _knownLossCount);
            Trace.WriteLine($"Browser Defender metadata watcher attachment failed: {ex.GetType().Name}.");
        }
    }

    private void Publish(BrowserProfileRoot root, string path, WatcherChangeTypes changeType)
    {
        if (!IsMetadataPath(root, path)) return;
        var observed = DateTimeOffset.UtcNow;
        Interlocked.Exchange(ref _lastObservedTicks, observed.UtcTicks);
        if (!_changes.Writer.TryWrite(new BrowserMetadataChange
            { Root = root, MetadataPath = path, ChangeType = changeType, ObservedAtUtc = observed }))
            Interlocked.Increment(ref _knownLossCount);
    }

    private static bool IsMetadataPath(BrowserProfileRoot root, string path)
    {
        try
        {
            var relative = Path.GetRelativePath(root.RootPath, path);
            if (Path.IsPathRooted(relative) || relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                return false;
            var segments = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var filename = segments[^1];
            if (root.BrowserType == Core.Enums.BrowserType.Firefox)
                return segments.Length == 2 && filename.Equals("extensions.json", StringComparison.OrdinalIgnoreCase);
            if (filename is "Preferences" or "Secure Preferences") return segments.Length <= 2;
            if (filename.Equals("manifest.json", StringComparison.OrdinalIgnoreCase))
                return segments.Length is 4 or 5 && segments.Any(item => item.Equals("Extensions", StringComparison.OrdinalIgnoreCase));
            return segments.Length is 1 or 2 && (filename.Equals("Default", StringComparison.OrdinalIgnoreCase)
                || filename.Equals("Extensions", StringComparison.OrdinalIgnoreCase)
                || filename.StartsWith("Profile ", StringComparison.Ordinal));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        { Trace.WriteLine($"Browser Defender metadata notification path rejected: {ex.GetType().Name}."); return false; }
    }

    /// <summary>Reads metadata notifications from a 128-item queue; the caller must perform bounded, authorized reconciliation.</summary>
    public IAsyncEnumerable<BrowserMetadataChange> ReadChangesAsync(CancellationToken cancellationToken = default) =>
        _changes.Reader.ReadAllAsync(cancellationToken);

    /// <summary>Returns actual attachment and loss state; watcher errors remain visible until the monitor is recreated.</summary>
    public BrowserInventoryMonitorHealth GetHealth()
    {
        lock (_gate)
        {
            var ticks = Interlocked.Read(ref _lastObservedTicks);
            var loss = Interlocked.Read(ref _knownLossCount);
            return new BrowserInventoryMonitorHealth
            {
                IsRunning = _started && !_disposed, RequestedRoots = _requestedRoots,
                ActiveWatchers = _watchers.Count, KnownLossCount = loss,
                RequiresReconciliation = _started && (loss > 0 || _watchers.Count < _requestedRoots),
                LastObservedAtUtc = ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero)
            };
        }
    }

    /// <summary>Stops observers and completes the queue; disposal never alters or removes any browser data.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            foreach (var watcher in _watchers) watcher.Dispose();
            _watchers.Clear();
            _changes.Writer.TryComplete();
        }
    }
}
