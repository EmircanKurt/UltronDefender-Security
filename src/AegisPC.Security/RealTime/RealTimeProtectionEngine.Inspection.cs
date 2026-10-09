using System.Diagnostics;
using AegisPC.Core.Enums;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.RealTime;

/// <summary>Owns bounded arrival retries and per-file gaps; native cancellation remains cooperative.</summary>
public partial class RealTimeProtectionEngine
{
    private sealed record ArrivalIdentity(long Sequence, string? Root);
    private readonly Dictionary<string, ArrivalIdentity> _arrivalInspections = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _inspectionGaps = new(StringComparer.OrdinalIgnoreCase);
    private long _arrivalSequence;
    private readonly HashSet<long> _pendingInspectionRetries = new();

    private ArrivalIdentity? BeginArrivalInspection(string path, long generation, CancellationToken ct)
    {
        lock (_lock)
        {
            if (!_isRunning || _engineGeneration != generation || ct.IsCancellationRequested) return null;
            if (_arrivalInspections.Count >= 1024 && !_arrivalInspections.ContainsKey(path))
            {
                _coverageDegraded = true;
                return null;
            }
            var identity = new ArrivalIdentity(++_arrivalSequence, FindWatchedRoot(path));
            _arrivalInspections[path] = identity;
            return identity;
        }
    }

    private bool IsCurrentArrival(string path, ArrivalIdentity identity, long generation, CancellationToken ct)
    {
        lock (_lock)
            return _isRunning && !ct.IsCancellationRequested && generation == _engineGeneration &&
                _arrivalInspections.TryGetValue(path, out var current) && current == identity &&
                (identity.Root == null || _watchedLocationsList.Contains(identity.Root));
    }

    private void RecordArrivalCoverage(string path, ArrivalIdentity identity, long generation, bool complete, CancellationToken ct)
    {
        lock (_lock)
        {
            if (!IsCurrentArrival(path, identity, generation, ct)) return;
            if (complete) _inspectionGaps.Remove(path);
            else if (_inspectionGaps.Count < 2048) _inspectionGaps.Add(path);
            else _coverageDegraded = true; // Bounded memory: overflow remains an explicit unresolved gap.
        }
    }

    private async Task<RealTimeVerdictResult?> InspectArrivalWithRetryAsync(NormalizedFileEvent evt,
        ArrivalIdentity identity, long generation, CancellationToken ct)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(10));
        var elapsed = Stopwatch.StartNew();
        RealTimeVerdictResult? result = null;
        try
        {
            for (int attempt = 0; attempt < 5; attempt++)
            {
                if (!IsCurrentArrival(evt.NormalizedPath, identity, generation, ct) || !File.Exists(evt.NormalizedPath)) return null;
                bool stable = await _stabilityChecker.WaitForFileStabilityAsync(evt.NormalizedPath, budget.Token);
                if (stable)
                {
                    using (RealtimeScanPriority.Enter())
                        result = await _verdictProcessor.InspectFileAsync(evt.NormalizedPath, budget.Token);
                    budget.Token.ThrowIfCancellationRequested();
                    if (!result.Retryable) return result;
                }
                else result = new RealTimeVerdictResult { RecommendedPolicy = RealTimePolicyAction.Observe,
                    Retryable = true, CoverageLimitations = ["FileStabilityUnavailable"] };
                if (!File.Exists(evt.NormalizedPath)) return null;
                if (attempt == 4 || elapsed.Elapsed >= TimeSpan.FromSeconds(10)) break;
                lock (_lock)
                    if (IsCurrentArrival(evt.NormalizedPath, identity, generation, ct)) _pendingInspectionRetries.Add(identity.Sequence);
                try { await Task.Delay(Math.Min(1000, 100 << attempt), budget.Token); }
                finally { lock (_lock) _pendingInspectionRetries.Remove(identity.Sequence); }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && budget.IsCancellationRequested)
        {
            // Awaited native operations are not abandoned. This is a cooperative budget, not a hard process deadline.
            result = new RealTimeVerdictResult { RecommendedPolicy = RealTimePolicyAction.Observe,
                CoverageLimitations = ["ArrivalInspectionBudgetExceeded"] };
        }
        result ??= new RealTimeVerdictResult { RecommendedPolicy = RealTimePolicyAction.Observe };
        result.Retryable = false;
        result.InspectionComplete = false;
        result.CoverageLimitations = result.CoverageLimitations.Append("ArrivalRetryBudgetExhausted").Distinct().ToArray();
        return result;
    }

    private void EndArrivalInspection(string path, ArrivalIdentity? identity)
    {
        lock (_lock)
            if (identity != null && _arrivalInspections.TryGetValue(path, out var current) && current == identity)
                _arrivalInspections.Remove(path);
    }
}
