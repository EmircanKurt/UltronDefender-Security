using System.Diagnostics;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Retains bounded aggregate timing histograms instead of one allocation/history entry per file.</summary>
internal sealed class ScanMeasurementRecorder : IDisposable
{
    private sealed class Volume
    {
        internal int Attempts, Finished, Active, Peak;
        internal long Bytes;
        internal readonly long[] Queue = new long[32], Analysis = new long[32];
    }
    private readonly object _sync = new();
    private readonly Dictionary<string, Volume> _volumes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly Process _process = Process.GetCurrentProcess();
    private readonly ScanProcessTelemetry _telemetry = new();
    private readonly TimeSpan? _cpuAtStart;

    internal ScanMeasurementRecorder()
    { try { _cpuAtStart = _process.TotalProcessorTime; } catch (InvalidOperationException) { } }

    internal IDisposable Begin(string path, long queuedAt)
    {
        string root = Path.GetPathRoot(Path.GetFullPath(path)) ?? "unknown";
        long bytes = 0;
        try { bytes = new FileInfo(path).Length; } catch (IOException) { } catch (UnauthorizedAccessException) { }
        long started = Stopwatch.GetTimestamp();
        lock (_sync)
        {
            if (!_volumes.TryGetValue(root, out var volume))
            {
                if (_volumes.Count >= 128) root = "other";
                if (!_volumes.TryGetValue(root, out volume)) _volumes[root] = volume = new();
            }
            volume.Attempts++; volume.Active++; volume.Peak = Math.Max(volume.Peak, volume.Active);
            volume.Bytes += bytes;
            Add(volume.Queue, Stopwatch.GetElapsedTime(queuedAt, started).TotalMilliseconds);
            _telemetry.Sample();
        }
        return new Measurement(() =>
        {
            lock (_sync)
            {
                var volume = _volumes[root];
                volume.Active--; volume.Finished++;
                Add(volume.Analysis, Stopwatch.GetElapsedTime(started).TotalMilliseconds);
                _telemetry.Sample();
            }
        });
    }

    internal ScanMeasurementSummary Snapshot()
    {
        lock (_sync)
        {
            _telemetry.Sample();
            double seconds = Math.Max(0.001, _clock.Elapsed.TotalSeconds);
            double? cpu = null;
            try { if (_cpuAtStart.HasValue) cpu = (_process.TotalProcessorTime - _cpuAtStart.Value).TotalMilliseconds; }
            catch (InvalidOperationException) { }
            return new()
            {
                ElapsedMs = seconds * 1000, ProcessCpuMs = cpu,
                PeakObservedWorkingSetMb = _telemetry.PeakObservedWorkingSetMb,
                Volumes = _volumes.Select(v => new VolumeScanMeasurement
                {
                    VolumeRoot = v.Key, Attempts = v.Value.Attempts, FinishedAttempts = v.Value.Finished,
                    PeakActiveWorkers = v.Value.Peak, LogicalInputBytes = v.Value.Bytes,
                    FilesPerSecond = v.Value.Finished / seconds, LogicalInputMiBPerSecond = v.Value.Bytes / 1048576.0 / seconds,
                    QueueP95UpperBoundMs = P95(v.Value.Queue), AnalysisP95UpperBoundMs = P95(v.Value.Analysis)
                }).ToList()
            };
        }
    }

    private static void Add(long[] bins, double ms)
    { int bin = Math.Clamp((int)Math.Ceiling(Math.Log2(Math.Max(1, ms))), 0, bins.Length - 1); bins[bin]++; }
    private static double P95(long[] bins)
    {
        long target = (long)Math.Ceiling(bins.Sum() * 0.95), count = 0;
        if (target == 0) return 0;
        for (int i = 0; i < bins.Length; i++) { count += bins[i]; if (count >= target) return Math.Pow(2, i); }
        return 0;
    }
    public void Dispose() { _telemetry.Dispose(); _process.Dispose(); }
    private sealed class Measurement(Action end) : IDisposable
    { private Action? _end = end; public void Dispose() => Interlocked.Exchange(ref _end, null)?.Invoke(); }
}
