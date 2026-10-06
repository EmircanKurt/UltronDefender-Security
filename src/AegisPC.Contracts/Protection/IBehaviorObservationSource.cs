namespace AegisPC.Contracts.Protection;

/// <summary>Reported process generation; not a native action identity or signed actor proof.</summary>
public sealed record BehaviorProcessIdentity(int Pid, DateTimeOffset StartedAtUtc, string BootId);
/// <summary>Local event families; coverage loss never establishes malicious activity.</summary>
public enum BehaviorObservationKind { ProcessStarted, FileWritten, StartupChanged, CoverageGap }
/// <summary>Reported writer mapping quality, not native-action authorization.</summary>
public enum BehaviorAttribution { Unknown, EtwThreadGeneration }
/// <summary>Local bounded observation. File watchers cannot set a verified writer identity.</summary>
public sealed record BehaviorObservation(string EventId, string FeatureId, BehaviorObservationKind Kind,
    BehaviorProcessIdentity? Actor, DateTimeOffset ObservedAtUtc, string Explanation,
    BehaviorAttribution Attribution = BehaviorAttribution.Unknown, int ReviewWeight = 10);
/// <summary>Bounded queue occupancy and cumulative acceptance/loss counters without file paths.</summary>
public sealed record BehaviorObservationHealth(int Pending, long Accepted, long Dropped, long Invalid);

/// <summary>Only enqueues in a native callback; asynchronous consumers do analysis outside that callback.</summary>
public interface IBehaviorObservationSource
{
    /// <summary>Nonblocking enqueue; invalid input or saturation returns false and updates health.</summary>
    bool TryPublish(BehaviorObservation observation);
    /// <summary>Single asynchronous consumer stream; cancellation ends observation consumption.</summary>
    IAsyncEnumerable<BehaviorObservation> ReadAllAsync(CancellationToken cancellationToken);
    /// <summary>Captures counters without attributing loss to an attacker.</summary>
    BehaviorObservationHealth CaptureHealth();
}
