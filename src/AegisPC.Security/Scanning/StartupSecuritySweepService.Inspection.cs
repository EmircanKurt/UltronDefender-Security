using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>Keeps sequential startup inspection cancellable and observable without abandoning background work or claiming incomplete files are clean.</summary>
public partial class StartupSecuritySweepService
{
    private readonly TimeSpan _inspectionTimeout;
    private ScanProcessTelemetry? _progressTelemetry;
    private Stopwatch? _progressClock;

    private async Task<RealTimeVerdictResult> InspectWithBudgetAsync(string path, StartupSweepProgress progress,
        IExternalScanRegistration? registration, CancellationToken cancellationToken)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(_inspectionTimeout);
        bool waitingReported = false;
        try
        {
            // Await the real worker even after budget expiry: native operations may not support cancellation.
            // This avoids orphaned workers retaining file locks or producing late actions after a reported timeout.
            var inspection = Task.Run(() => _realTimeEngine.InspectFileAsync(path, budget.Token), budget.Token);
            while (!inspection.IsCompleted)
            {
                await Task.WhenAny(inspection, Task.Delay(TimeSpan.FromSeconds(1)));
                if (!inspection.IsCompleted)
                {
                    if (budget.IsCancellationRequested && !waitingReported)
                    {
                        waitingReported = true;
                        Interlocked.Increment(ref _cancellingWorkers);
                        _logger?.LogWarning("Startup inspection cancellation is pending; awaiting the actual worker without abandoning file locks.");
                    }
                }
            }
            var verdict = await inspection;
            cancellationToken.ThrowIfCancellationRequested();
            budget.Token.ThrowIfCancellationRequested();
            return verdict;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && budget.IsCancellationRequested)
        {
            _logger?.LogWarning("Startup file inspection exceeded its {TimeoutMs} ms cooperative budget.", _inspectionTimeout.TotalMilliseconds);
            return new RealTimeVerdictResult
            {
                Verdict = RealTimeVerdict.Unknown,
                RecommendedPolicy = RealTimePolicyAction.Observe,
                InspectionComplete = false,
                CoverageLimitations = ["StartupInspectionTimedOut"],
                ThreatDescription = "Dosya incelemesi süre sınırını aştı; dosyanın güvenli olduğu doğrulanmadı.",
                Evidences = ["StartupInspectionTimedOut"]
            };
        }
        finally
        {
            // Only the aggregation consumer publishes telemetry; workers never sample its mutable clock.
            if (waitingReported)
                Interlocked.Decrement(ref _cancellingWorkers);
        }
    }

    private ScanCoverageSummary CreateSweepCoverage(StartupSweepResult result)
    {
        var coverage = _discoveryCoverage;
        if (result.IncompleteCount > 0) coverage.RecordLimitation("StartupInspectionIncomplete");
        if (result.TimedOutCount > 0) coverage.RecordLimitation("StartupInspectionTimedOut");
        return coverage;
    }
}
