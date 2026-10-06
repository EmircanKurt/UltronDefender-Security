namespace AegisPC.Core.Models;

/// <summary>Measured inspection throughput; logical input bytes are not physical disk reads or malware effectiveness.</summary>
public sealed class ScanMeasurementSummary
{
    /// <summary>Monotonic wall duration of the measured pipeline.</summary>
    public double ElapsedMs { get; init; }
    /// <summary>Scanner-process CPU delta; null denotes a failed measurement.</summary>
    public double? ProcessCpuMs { get; init; }
    /// <summary>Largest working set actually sampled during this pipeline, not a guaranteed instantaneous peak.</summary>
    public double PeakObservedWorkingSetMb { get; init; }
    /// <summary>Hash time is unknown until hash-stage instrumentation is available; never inferred from CPU.</summary>
    public double? HashStageMs { get; init; }
    /// <summary>Content-stage time is unknown when configured detectors do not expose separate timings.</summary>
    public double? ContentStageMs { get; init; }
    /// <summary>Bounded aggregate measurements for each observed volume root.</summary>
    public List<VolumeScanMeasurement> Volumes { get; init; } = [];
}

/// <summary>Per-volume measurements distinguish queue/admission delay from file-analysis time.</summary>
public sealed class VolumeScanMeasurement
{
    /// <summary>Observed root within the selected scope; it is not firmware or medium identity.</summary>
    public string VolumeRoot { get; init; } = string.Empty;
    /// <summary>Analyses admitted, including interrupted attempts.</summary>
    public int Attempts { get; init; }
    /// <summary>Analyses whose owned scope ended; this is not a clean-file count.</summary>
    public int FinishedAttempts { get; init; }
    /// <summary>Largest admitted worker count observed on this volume.</summary>
    public int PeakActiveWorkers { get; init; }
    /// <summary>Logical size of admitted files; cache/filesystem effects preclude interpreting it as physical I/O.</summary>
    public long LogicalInputBytes { get; init; }
    /// <summary>Finished attempts per second over the common pipeline duration.</summary>
    public double FilesPerSecond { get; init; }
    /// <summary>Logical input MiB per second, not physical disk transfer rate.</summary>
    public double LogicalInputMiBPerSecond { get; init; }
    /// <summary>p95 upper bound from a fixed log2 histogram; queue time includes worker-admission waiting.</summary>
    public double QueueP95UpperBoundMs { get; init; }
    /// <summary>p95 upper bound from a fixed log2 histogram, not a falsely precise percentile.</summary>
    public double AnalysisP95UpperBoundMs { get; init; }
}
