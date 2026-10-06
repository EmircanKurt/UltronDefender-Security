namespace AegisPC.Security.UltronAI;

/// <summary>Bounded robust resource/behavior baseline used only for review ordering, not malware probability or intervention authority.</summary>
public sealed class BehaviorReviewStatistics
{
    private readonly Queue<double> _samples = new();
    private readonly object _gate = new();
    private double? _ewma;
    /// <summary>Adds a finite, nonnegative sample to a 128-sample local window.</summary>
    public bool Add(double value)
    {
        if (!double.IsFinite(value) || value < 0) return false;
        lock (_gate)
        {
            if (_samples.Count == 128) _samples.Dequeue();
            _samples.Enqueue(value);
            _ewma = _ewma is { } previous ? 0.2 * value + 0.8 * previous : value;
        }
        return true;
    }
    /// <summary>Returns an explicitly missing baseline until a sample exists; MAD=0 is not infinite certainty.</summary>
    public (int Count, double? Ewma, double? Median, double? Mad) Snapshot()
    {
        lock (_gate)
        {
            if (_samples.Count == 0) return (0, null, null, null);
            var sorted = _samples.Order().ToArray();
            double median = Median(sorted);
            double mad = Median(sorted.Select(x => Math.Abs(x - median)).Order().ToArray());
            return (sorted.Length, _ewma, median, mad);
        }
    }
    private static double Median(double[] sorted) => sorted.Length % 2 != 0 ? sorted[sorted.Length / 2]
        : sorted[sorted.Length / 2 - 1] / 2 + sorted[sorted.Length / 2] / 2;
}
