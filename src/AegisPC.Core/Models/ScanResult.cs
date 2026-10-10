using System;
using System.Collections.Generic;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

/// <summary>Retains one scan's terminal lifecycle, observed findings, counters, and independent coverage gaps.</summary>
public class ScanResult
{
    /// <summary>The inspection mode used for this result.</summary>
    public ScanType ScanType { get; set; }
    /// <summary>The UTC instant at which the scan began.</summary>
    public DateTime StartedAt { get; set; }
    /// <summary>The UTC terminal instant, or null while the scan is running.</summary>
    public DateTime? CompletedAt { get; set; }
    /// <summary>The scan lifecycle outcome; completion alone does not establish complete coverage.</summary>
    public ScanStatus Status { get; set; }
    /// <summary>The number of discovered inspection candidates.</summary>
    public int TotalFiles { get; set; }
    /// <summary>The number of files analyzed before the terminal outcome.</summary>
    public int ScannedFiles { get; set; }
    /// <summary>The number of files omitted by the recorded scan policy.</summary>
    public int SkippedFiles { get; set; }
    /// <summary>The number of per-file inspections that failed.</summary>
    public int FailedFiles { get; set; }
    /// <summary>The number of per-file inspections whose time budget expired.</summary>
    public int TimedOutFiles { get; set; }
    /// <summary>The number of retained findings, independent of the terminal lifecycle status.</summary>
    public int FindingsCount => Findings.Count;
    /// <summary>The requested target for custom scans; stored reports may contain this private path.</summary>
    public string? CustomPath { get; set; }
    /// <summary>The measured scan duration in milliseconds.</summary>
    public long ElapsedMs { get; set; }
    /// <summary>The findings observed before completion, cancellation, or failure.</summary>
    public List<SecurityFinding> Findings { get; set; } = new();
    /// <summary>Inspection gaps independent of the scan lifecycle status.</summary>
    public ScanCoverageSummary Coverage { get; set; } = new();
    /// <summary>Structured privacy-safe diagnostics for a failed scan; older reports omit this optional value.</summary>
    public ScanFailureInfo? FailureInfo { get; set; }
    /// <summary>Optional measured pipeline/volume telemetry; absent for old reports and uninstrumented scanners.</summary>
    public ScanMeasurementSummary? Measurements { get; set; }
}
