namespace AegisPC.Core.Models;

/// <summary>Measured inspection throughput; logical input bytes are not physical disk reads or malware effectiveness.</summary>
public sealed class ScanMeasurementSummary
{
    /// <summary>Monotonic wall duration of the measured pipeline.</summary>
    public double ElapsedMs { get; init; }
    /// <summary>Scanner-process CPU delta; null denotes a failed measurement.</summary>
    public double? ProcessCpuMs { get; init; }
    /// <summary>Host-process CPU delta divided by monotonic pipeline wall time and logical processor count, 0–100%; includes unrelated activity in this process.</summary>
    public double? ProcessCpuPercent { get; init; }
    /// <summary>Logical processor count used to normalize the host-process CPU measurement.</summary>
    public int CpuNormalizationProcessorCount { get; init; }
    /// <summary>Largest working set actually sampled during this pipeline, not a guaranteed instantaneous peak.</summary>
    public double PeakObservedWorkingSetMb { get; init; }
    /// <summary>False means the observed working-set peak is unavailable, rather than a measured zero.</summary>
    public bool PeakObservedWorkingSetAvailable { get; init; }
    /// <summary>Physical disk throughput is unavailable without independent I/O instrumentation; logical file sizes must not populate it.</summary>
    public double? PhysicalInputMiBPerSecond { get; init; }
    /// <summary>Sum of actually instrumented discovery wall durations; overlapping worker stages are not additive pipeline elapsed time.</summary>
    public double? DiscoveryStageMs { get; init; }
    /// <summary>Sum of actually instrumented file-stability wall durations; null means no stability stage was measured.</summary>
    public double? StabilityStageMs { get; init; }
    /// <summary>Hash time is unknown until hash-stage instrumentation is available; never inferred from CPU.</summary>
    public double? HashStageMs { get; init; }
    /// <summary>Content-stage time is unknown when configured detectors do not expose separate timings.</summary>
    public double? ContentStageMs { get; init; }
    /// <summary>Sum of actually instrumented detector wall durations, including interrupted attempts; null means no detector stage was measured.</summary>
    public double? DetectorStageMs { get; init; }
    /// <summary>How many instrumented scopes contributed to each stage; this does not claim every configured stage was instrumented.</summary>
    public List<ScanStageMeasurement> Stages { get; init; } = [];
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
    /// <summary>Analyses ended by an explicit outcome or interruption; this does not mean the result was delivered or the file was clean.</summary>
    public int FinishedAttempts { get; init; }
    /// <summary>Returned successful operational outcomes, independent of reported coverage or findings.</summary>
    public int SuccessfulAttempts { get; init; }
    /// <summary>Returned failed operational outcomes; partial coverage may coexist with a failure.</summary>
    public int FailedAttempts { get; init; }
    /// <summary>Attempts with a reported timeout outcome.</summary>
    public int TimedOutAttempts { get; init; }
    /// <summary>Attempts deliberately skipped by the scanner.</summary>
    public int SkippedAttempts { get; init; }
    /// <summary>Owned attempt scopes which ended without a reported terminal result, such as cancellation.</summary>
    public int InterruptedAttempts { get; init; }
    /// <summary>Completed outcomes which explicitly reported full configured coverage; never inferred from successful return.</summary>
    public int CompleteCoverageAttempts { get; init; }
    /// <summary>Completed outcomes which explicitly reported incomplete configured coverage.</summary>
    public int PartialCoverageAttempts { get; init; }
    /// <summary>Completed outcomes without an explicit coverage report, including unreported/interrupted attempts.</summary>
    public int UnknownCoverageAttempts { get; init; }
    /// <summary>Supplementary count of terminal results reported from cache; also present in the operational outcome and coverage counts.</summary>
    public int CachedAttempts { get; init; }
    /// <summary>Supplementary count of completed results reporting an intentional trust/allowlist policy bypass; not full detector coverage.</summary>
    public int PolicyBypassedAttempts { get; init; }
    /// <summary>Largest admitted worker count observed on this volume.</summary>
    public int PeakActiveWorkers { get; init; }
    /// <summary>Sum of file sizes actually observed at admission; unknown sizes are omitted, and this is never physical I/O.</summary>
    public long LogicalInputBytes { get; init; }
    /// <summary>False means logical byte totals/throughput omit at least one unknown file size and must not be presented as complete input throughput.</summary>
    public bool LogicalInputSizesComplete { get; init; }
    /// <summary>Admitted attempts whose file size could not be queried.</summary>
    public int UnknownLogicalInputSizeAttempts { get; init; }
    /// <summary>Finished attempts per second over the common pipeline duration.</summary>
    public double FilesPerSecond { get; init; }
    /// <summary>Logical input MiB per second, not physical disk transfer rate.</summary>
    public double LogicalInputMiBPerSecond { get; init; }
    /// <summary>p95 upper bound from a fixed log2 histogram; queue time includes worker-admission waiting.</summary>
    public double QueueP95UpperBoundMs { get; init; }
    /// <summary>p95 upper bound from a fixed log2 histogram, not a falsely precise percentile.</summary>
    public double AnalysisP95UpperBoundMs { get; init; }
    /// <summary>p95 upper bound for the separately measured result-channel write wait; null when no result-channel write was measured.</summary>
    public double? OutputQueueP95UpperBoundMs { get; init; }
    /// <summary>Number of result-channel write waits actually measured, including writes interrupted by cancellation.</summary>
    public int OutputQueueWaitSamples { get; init; }
}

/// <summary>Bounded stage totals describe measured scopes, not physical I/O or detector effectiveness.</summary>
public sealed class ScanStageMeasurement
{
    public string Stage { get; init; } = string.Empty;
    public long Samples { get; init; }
    public double TotalMs { get; init; }
}
