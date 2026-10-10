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
    private sealed class ActorWindow
    {
        internal readonly List<BehaviorObservation> Events = [];
        internal DateTimeOffset LastObserved;
        internal DateTimeOffset LossExpires;
    }
    private readonly Dictionary<BehaviorProcessIdentity, ActorWindow> _actors = new();
    private readonly Dictionary<BehaviorProcessIdentity, DateTimeOffset> _evictedActors = new();
    private DateTimeOffset _untrackedLossUntil;
    private DateTimeOffset _nextCleanup;
    private long _evictions;
    private readonly BehaviorReviewStatistics _statistics = new();
    /// <summary>Bounded review statistics; none are calibrated malware probabilities.</summary>
    public (int Count, double? Ewma, double? Median, double? Mad) Statistics => _statistics.Snapshot();
    /// <summary>Discards retained actor events when AI review is disabled; historical loss stays recorded.</summary>
    public void Clear()
    {
        lock (_gate)
        { _actors.Clear(); _evictedActors.Clear(); _untrackedLossUntil = default; }
    }

    /// <summary>Rejects missing, future or stale identity, and never infers a writer from a pathname/lock owner.</summary>
    public BehaviorWindowReview Observe(BehaviorObservation observation, DateTimeOffset? nowUtc = null)
    {
        ArgumentNullException.ThrowIfNull(observation);
        DateTimeOffset now = nowUtc ?? DateTimeOffset.UtcNow;
        var actor = observation.Actor;
        bool valid = actor is { Pid: > 4 } && actor.StartedAtUtc > DateTimeOffset.UnixEpoch &&
            !string.IsNullOrWhiteSpace(actor.BootId) && actor.BootId.Length <= 128 &&
            !string.IsNullOrWhiteSpace(observation.EventId) && !string.IsNullOrWhiteSpace(observation.FeatureId) &&
            observation.ObservedAtUtc >= actor.StartedAtUtc && observation.ObservedAtUtc <= now.AddSeconds(5) &&
            observation.ObservedAtUtc >= now.AddMinutes(-5) && Enum.IsDefined(observation.Kind) &&
            observation.Kind != BehaviorObservationKind.CoverageGap &&
            (observation.Kind != BehaviorObservationKind.FileWritten || observation.Attribution == BehaviorAttribution.EtwThreadGeneration);
        BehaviorObservation[] retained;
        bool complete;
        int actors;
        long evictions;
        lock (_gate)
        {
            if (valid && now >= _nextCleanup)
            {
                foreach (var key in _actors.Where(x => x.Value.LastObserved < now.AddMinutes(-5)).Select(x => x.Key).ToArray())
                    _actors.Remove(key);
                foreach (var key in _evictedActors.Where(x => x.Value <= now).Select(x => x.Key).ToArray())
                    _evictedActors.Remove(key);
                _nextCleanup = now.AddSeconds(1);
            }
            retained = [];
            complete = false;
            if (valid)
            {
                if (!_actors.TryGetValue(actor!, out var window))
                {
                    if (_actors.Count >= MaxActors)
                    {
                        var oldest = _actors.MinBy(x => x.Value.LastObserved).Key;
                        if (_evictedActors.Count >= MaxActors && !_evictedActors.ContainsKey(oldest))
                        {
                            // Even loss markers are bounded. If attribution history itself is lost,
                            // temporarily report a global gap rather than invent complete coverage.
                            _untrackedLossUntil = now.AddMinutes(5);
                            _evictedActors.Remove(_evictedActors.MinBy(x => x.Value).Key);
                        }
                        _evictedActors[oldest] = _actors[oldest].LastObserved.AddMinutes(5);
                        _actors.Remove(oldest); _evictions++;
                    }
                    window = new() { LossExpires = _evictedActors.GetValueOrDefault(actor!) };
                    _evictedActors.Remove(actor!);
                    _actors.Add(actor!, window);
                }
                var events = window.Events;
                events.RemoveAll(e => e.ObservedAtUtc < now.AddMinutes(-5));
                if (!events.Any(e => e.EventId == observation.EventId && e.FeatureId == observation.FeatureId))
                {
                    if (events.Count == MaxEventsPerActor)
                    {
                        var oldest = events.MinBy(e => e.ObservedAtUtc)!;
                        events.Remove(oldest); _evictions++;
                        var expires = oldest.ObservedAtUtc.AddMinutes(5);
                        if (expires > window.LossExpires) window.LossExpires = expires;
                    }
                    events.Add(observation);
                }
                if (observation.ObservedAtUtc > window.LastObserved) window.LastObserved = observation.ObservedAtUtc;
                retained = events.ToArray();
                complete = window.LossExpires <= now && _untrackedLossUntil <= now;
            }
            actors = _actors.Count; evictions = _evictions;
        }
        // Scoring/sorting does not hold the inventory lock; invalid observations do not poison baselines.
        return Review(valid ? actor : null, retained, now, complete, actors, evictions, valid);
    }

    private BehaviorWindowReview Review(BehaviorProcessIdentity? actor, IEnumerable<BehaviorObservation> events,
        DateTimeOffset now, bool complete, int actors, long evictions, bool addStatistics)
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
        if (addStatistics) _statistics.Add(longWindow.ReviewPriority);
        return new(actor, shortWindow, longWindow, complete, actors, evictions);
    }
}
