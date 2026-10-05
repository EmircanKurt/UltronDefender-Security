using AegisPC.Contracts.Protection;

namespace AegisPC.Security.UltronAI;

/// <summary>Two observation windows for a reported actor; priority is not malware probability or intervention authority.</summary>
public sealed record BehaviorWindowReview(BehaviorProcessIdentity? Actor, UltronDecision ShortWindow,
    UltronDecision LongWindow, bool AttributionComplete, int RetainedActors, long Evictions);

/// <summary>
/// Correlates process/file/persistence observations by full generation in 30-second/5-minute windows.
/// Same features are deduplicated; the common decision engine supplies per-family caps. No action executor.
/// </summary>
public sealed class BehaviorWindowCorrelator(IUltronDecisionEngine decisions)
{
    private const int MaxActors = 512;
    private const int MaxEventsPerActor = 64;
    private readonly object _gate = new();
    private readonly Dictionary<BehaviorProcessIdentity, List<BehaviorObservation>> _actors = new();
    private long _evictions;
    private readonly BehaviorReviewStatistics _statistics = new();
    /// <summary>Bounded review statistics; none are calibrated malware probabilities.</summary>
    public (int Count, double? Ewma, double? Median, double? Mad) Statistics => _statistics.Snapshot();
    /// <summary>Discards retained actor events when AI review is disabled; historical loss stays recorded.</summary>
    public void Clear() { lock (_gate) _actors.Clear(); }

    /// <summary>Rejects missing, future or stale identity, and never infers a writer from a pathname/lock owner.</summary>
    public BehaviorWindowReview Observe(BehaviorObservation observation, DateTimeOffset? nowUtc = null)
    {
        ArgumentNullException.ThrowIfNull(observation);
        DateTimeOffset now = nowUtc ?? DateTimeOffset.UtcNow;
        lock (_gate)
        {
            foreach (var key in _actors.Where(x => x.Value.All(e => e.ObservedAtUtc < now.AddMinutes(-5))).Select(x => x.Key).ToArray())
                _actors.Remove(key);
            var actor = observation.Actor;
            bool valid = actor is { Pid: > 4 } && actor.StartedAtUtc > DateTimeOffset.UnixEpoch &&
                !string.IsNullOrWhiteSpace(actor.BootId) && actor.BootId.Length <= 128 &&
                observation.ObservedAtUtc >= actor.StartedAtUtc && observation.ObservedAtUtc <= now.AddSeconds(5) &&
                observation.ObservedAtUtc >= now.AddMinutes(-5) &&
                observation.Kind != BehaviorObservationKind.CoverageGap &&
                (observation.Kind != BehaviorObservationKind.FileWritten || observation.Attribution == BehaviorAttribution.EtwThreadGeneration);
            if (!valid) return Review(null, [], now, false);
            if (!_actors.TryGetValue(actor!, out var events))
            {
                if (_actors.Count >= MaxActors)
                {
                    var oldest = _actors.MinBy(x => x.Value.Max(e => e.ObservedAtUtc)).Key;
                    _actors.Remove(oldest); _evictions++;
                }
                events = []; _actors.Add(actor!, events);
            }
            events.RemoveAll(e => e.ObservedAtUtc < now.AddMinutes(-5));
            if (!events.Any(e => e.EventId == observation.EventId && e.FeatureId == observation.FeatureId))
            {
                if (events.Count == MaxEventsPerActor) { events.RemoveAt(0); _evictions++; }
                events.Add(observation);
            }
            return Review(actor, events, now, _evictions == 0);
        }
    }

    private BehaviorWindowReview Review(BehaviorProcessIdentity? actor, IEnumerable<BehaviorObservation> events,
        DateTimeOffset now, bool complete)
    {
        UltronDecision Window(TimeSpan span)
        {
            var evidence = events.Where(e => e.ObservedAtUtc >= now - span)
                .GroupBy(e => (e.Kind, e.FeatureId)).Select(g => g.OrderByDescending(e => e.ReviewWeight).First())
                .Select(e => new ProtectionEvidence(e.EventId, e.FeatureId, e.Kind switch
                { BehaviorObservationKind.FileWritten => ProtectionEvidenceFamily.FileIo,
                  BehaviorObservationKind.StartupChanged => ProtectionEvidenceFamily.Persistence,
                  _ => ProtectionEvidenceFamily.Process }, Math.Clamp(e.ReviewWeight, 0, 25), e.ObservedAtUtc, e.Explanation)).ToArray();
            return decisions.Evaluate(new(null, null, evidence, complete, now));
        }
        var shortWindow = Window(TimeSpan.FromSeconds(30));
        var longWindow = Window(TimeSpan.FromMinutes(5));
        _statistics.Add(longWindow.ReviewPriority);
        return new(actor, shortWindow, longWindow, complete, _actors.Count, _evictions);
    }
}

