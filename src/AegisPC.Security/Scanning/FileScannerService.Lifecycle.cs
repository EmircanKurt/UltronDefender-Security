using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Retains invocation-local observations when directory scanning is interrupted.</summary>
public partial class FileScannerService
{
    private ScanResult CreateInterruptedScanResult(string path, ScanType scanType,
        Stopwatch stopwatch, ScanCoverageSummary coverage, ConcurrentBag<SecurityFinding> findings,
        (int Total, int Scanned, int Skipped, int Failed, int TimedOut) counts, bool cancelled)
    {
        stopwatch.Stop();
        coverage.RecordLimitation(cancelled ? "ScanCancelledBeforeCompletion" : "ScannerTerminatedBeforeResult");
        return new ScanResult
        {
            ScanType = scanType,
            CustomPath = path,
            StartedAt = DateTime.UtcNow.Subtract(stopwatch.Elapsed),
            CompletedAt = DateTime.UtcNow,
            ElapsedMs = stopwatch.ElapsedMilliseconds,
            Status = cancelled ? ScanStatus.Cancelled : ScanStatus.Failed,
            TotalFiles = counts.Total,
            ScannedFiles = counts.Scanned,
            SkippedFiles = counts.Skipped,
            FailedFiles = counts.Failed,
            TimedOutFiles = counts.TimedOut,
            Findings = findings.ToList(),
            Coverage = coverage,
            Measurements = _queueCoordinator.LastMeasurements
        };
    }
}
