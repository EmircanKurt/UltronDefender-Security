using System.Diagnostics;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Retains bounded aggregate timing histograms instead of one allocation/history entry per file.</summary>
internal sealed class ScanMeasurementRecorder : IDisposable
{
    internal sealed class Volume
    {
        internal int Attempts, Finished, Active, Peak, Success, Failed, Timeout, Skipped, Interrupted;
        internal int CompleteCoverage, PartialCoverage, UnknownCoverage, Cached, PolicyBypassed, OutputSamples, UnknownSize;
        internal long Bytes;
        internal readonly long[] Queue = new long[32], Analysis = new long[32], OutputQueue = new long[32];
    }
    private readonly object _sync = new();
    private readonly Dictionary<string, Volume> _volumes = new(StringComparer.OrdinalIgnoreCase);
    private readonly double[] _stageMs = new double[5];
    private readonly long[] _stageSamples = new long[5];
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly Process _process = Process.GetCurrentProcess();
    private readonly ScanProcessTelemetry _telemetry = new();
    private readonly TimeSpan? _cpuAtStart;
    private readonly Action<ScanStageTiming, double> _stageSink;
    private int _disposed;

    internal ScanMeasurementRecorder()
    {
        _stageSink = RecordStage;
        try { _cpuAtStart = _process.TotalProcessorTime; }
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception) { }
        catch (NotSupportedException) { }
    }

    /// <summary>Activates stages for discovery outside an admitted file attempt; callers measure only the concrete operation.</summary>
    internal IDisposable BeginPipelineStages() => ScanStageMeasurements.Activate(_stageSink);

    internal Attempt Begin(string path, long queuedAt)
    {
        string root;
        try { root = Path.GetPathRoot(Path.GetFullPath(path)) ?? "unknown"; }
        catch (ArgumentException) { root = "unknown"; }
        catch (NotSupportedException) { root = "unknown"; }
        long bytes = 0;
        bool sizeKnown = false;
        try { bytes = new FileInfo(path).Length; sizeKnown = true; }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch (ArgumentException) { }
        catch (NotSupportedException) { }
        long started = Stopwatch.GetTimestamp();
        Volume volume;
        lock (_sync)
        {
            if (!_volumes.TryGetValue(root, out volume!))
            {
                if (_volumes.Count >= 128) root = "other";
                if (!_volumes.TryGetValue(root, out volume!)) _volumes[root] = volume = new();
            }
            volume.Attempts++; volume.Active++; volume.Peak = Math.Max(volume.Peak, volume.Active);
            volume.Bytes += bytes;
            if (!sizeKnown) volume.UnknownSize++;
            Add(volume.Queue, Stopwatch.GetElapsedTime(queuedAt, started).TotalMilliseconds);
            _telemetry.Sample();
        }
        return new Attempt(this, volume, Stopwatch.GetTimestamp(), BeginPipelineStages());
    }

    private void RecordStage(ScanStageTiming stage, double milliseconds)
    {
        lock (_sync)
        {
            if (_disposed != 0) return;
            int index = (int)stage;
            _stageMs[index] += milliseconds;
            _stageSamples[index]++;
        }
    }

    internal ScanMeasurementSummary Snapshot()
    {
        lock (_sync)
        {
            _telemetry.Sample();
            double seconds = Math.Max(0.001, _clock.Elapsed.TotalSeconds);
            double? cpu = null;
            try { if (_cpuAtStart.HasValue) cpu = Math.Max(0, (_process.TotalProcessorTime - _cpuAtStart.Value).TotalMilliseconds); }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            catch (NotSupportedException) { }
            double? Stage(ScanStageTiming stage) => _stageSamples[(int)stage] > 0 ? _stageMs[(int)stage] : null;
            return new()
            {
                ElapsedMs = seconds * 1000, ProcessCpuMs = cpu,
                ProcessCpuPercent = cpu.HasValue ? ScanProcessTelemetry.CalculateCpuPercent(TimeSpan.FromMilliseconds(cpu.Value), TimeSpan.FromSeconds(seconds), Environment.ProcessorCount) : null,
                CpuNormalizationProcessorCount = Environment.ProcessorCount,
                PeakObservedWorkingSetMb = _telemetry.PeakObservedWorkingSetMb,
                PeakObservedWorkingSetAvailable = _telemetry.HasWorkingSetSample,
                DiscoveryStageMs = Stage(ScanStageTiming.Discovery), StabilityStageMs = Stage(ScanStageTiming.Stability),
                HashStageMs = Stage(ScanStageTiming.Hash), ContentStageMs = Stage(ScanStageTiming.Content), DetectorStageMs = Stage(ScanStageTiming.Detector),
                Stages = Enum.GetValues<ScanStageTiming>().Where(s => _stageSamples[(int)s] > 0).Select(s => new ScanStageMeasurement
                { Stage = s.ToString(), Samples = _stageSamples[(int)s], TotalMs = _stageMs[(int)s] }).ToList(),
                Volumes = _volumes.Select(v => new VolumeScanMeasurement
                {
                    VolumeRoot = v.Key, Attempts = v.Value.Attempts, FinishedAttempts = v.Value.Finished,
                    SuccessfulAttempts = v.Value.Success, FailedAttempts = v.Value.Failed, TimedOutAttempts = v.Value.Timeout,
                    SkippedAttempts = v.Value.Skipped, InterruptedAttempts = v.Value.Interrupted,
                    CompleteCoverageAttempts = v.Value.CompleteCoverage, PartialCoverageAttempts = v.Value.PartialCoverage, UnknownCoverageAttempts = v.Value.UnknownCoverage,
                    CachedAttempts = v.Value.Cached, PolicyBypassedAttempts = v.Value.PolicyBypassed, PeakActiveWorkers = v.Value.Peak, LogicalInputBytes = v.Value.Bytes,
                    LogicalInputSizesComplete = v.Value.UnknownSize == 0, UnknownLogicalInputSizeAttempts = v.Value.UnknownSize,
                    FilesPerSecond = v.Value.Finished / seconds, LogicalInputMiBPerSecond = v.Value.Bytes / 1048576.0 / seconds,
                    QueueP95UpperBoundMs = P95(v.Value.Queue), AnalysisP95UpperBoundMs = P95(v.Value.Analysis),
                    OutputQueueP95UpperBoundMs = v.Value.OutputSamples > 0 ? P95(v.Value.OutputQueue) : null, OutputQueueWaitSamples = v.Value.OutputSamples
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
    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed != 0) return;
            _disposed = 1;
            _telemetry.Dispose(); _process.Dispose();
        }
    }

    /// <summary>Analysis ends at the reported result, before pacing, progress observers or the result-channel write.</summary>
    internal sealed class Attempt : IDisposable
    {
        private readonly ScanMeasurementRecorder _owner;
        private readonly Volume _volume;
        private readonly long _started;
        private IDisposable? _stages;
        private int _finished;
        internal Attempt(ScanMeasurementRecorder owner, Volume volume, long started, IDisposable stages)
        { _owner = owner; _volume = volume; _started = started; _stages = stages; }

        internal void Complete(FileScanDetailedResult result) => Complete(result.Outcome, result.InspectionComplete, result.IsFromCache, result.IsSignedClean);

        internal void Complete(FileScanOutcome outcome, bool? inspectionComplete = null, bool fromCache = false, bool policyBypassed = false) => Finish(outcome, inspectionComplete, fromCache, policyBypassed);

        private void Finish(FileScanOutcome? outcome, bool? inspectionComplete, bool fromCache, bool policyBypassed)
        {
            double milliseconds = Stopwatch.GetElapsedTime(_started).TotalMilliseconds;
            if (Interlocked.Exchange(ref _finished, 1) != 0) return;
            lock (_owner._sync)
            {
                _volume.Active--; _volume.Finished++;
                switch (outcome)
                {
                    case FileScanOutcome.Success: _volume.Success++; break;
                    case FileScanOutcome.Failed: _volume.Failed++; break;
                    case FileScanOutcome.Timeout: _volume.Timeout++; break;
                    case FileScanOutcome.Skipped: _volume.Skipped++; break;
                    default: _volume.Interrupted++; break;
                }
                if (inspectionComplete == true) _volume.CompleteCoverage++;
                else if (inspectionComplete == false) _volume.PartialCoverage++;
                else _volume.UnknownCoverage++;
                if (fromCache) _volume.Cached++;
                if (policyBypassed) _volume.PolicyBypassed++;
                Add(_volume.Analysis, milliseconds);
                _owner._telemetry.Sample();
            }
        }

        internal IDisposable MeasureOutputQueueWait()
        {
            long started = Stopwatch.GetTimestamp();
            return new Once(() =>
            {
                double milliseconds = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                lock (_owner._sync)
                {
                    _volume.OutputSamples++;
                    Add(_volume.OutputQueue, milliseconds);
                }
            });
        }

        public void Dispose()
        {
            Finish(null, null, false, false);
            Interlocked.Exchange(ref _stages, null)?.Dispose();
        }
    }

    private sealed class Once(Action end) : IDisposable
    { private Action? _end = end; public void Dispose() => Interlocked.Exchange(ref _end, null)?.Invoke(); }
}
