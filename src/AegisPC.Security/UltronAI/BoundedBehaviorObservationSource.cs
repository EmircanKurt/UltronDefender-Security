using System.Threading.Channels;
using AegisPC.Contracts.Protection;

namespace AegisPC.Security.UltronAI;

/// <summary>Bounded callback queue with explicit loss. No filesystem access, scoring or native action on publication.</summary>
public sealed class BoundedBehaviorObservationSource : IBehaviorObservationSource
{
    private readonly Channel<BehaviorObservation> _queue;
    private long _accepted, _dropped, _invalid;
    /// <summary>Creates a single-reader queue; capacities outside 1–8192 are rejected.</summary>
    public BoundedBehaviorObservationSource(int capacity = 2048)
    {
        if (capacity is < 1 or > 8192) throw new ArgumentOutOfRangeException(nameof(capacity));
        _queue = Channel.CreateBounded<BehaviorObservation>(new BoundedChannelOptions(capacity)
        { FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = false, AllowSynchronousContinuations = false });
    }
    /// <summary>Enqueues bounded input without waiting; saturation and invalid input remain visible.</summary>
    public bool TryPublish(BehaviorObservation observation)
    {
        if (observation == null || observation.EventId is not { Length: > 0 and <= 128 } ||
            observation.FeatureId is not { Length: > 0 and <= 128 } || observation.Explanation is not { Length: <= 1024 } ||
            observation.ObservedAtUtc == default || !Enum.IsDefined(observation.Kind) || !Enum.IsDefined(observation.Attribution))
        { Interlocked.Increment(ref _invalid); return false; }
        if (!_queue.Writer.TryWrite(observation)) { Interlocked.Increment(ref _dropped); return false; }
        Interlocked.Increment(ref _accepted);
        return true;
    }
    /// <summary>Reads outside native callbacks; cancellation propagates to the sole consumer.</summary>
    public IAsyncEnumerable<BehaviorObservation> ReadAllAsync(CancellationToken cancellationToken) => _queue.Reader.ReadAllAsync(cancellationToken);
    /// <summary>Captures path-free cumulative loss and current queue occupancy.</summary>
    public BehaviorObservationHealth CaptureHealth() => new(_queue.Reader.Count, Interlocked.Read(ref _accepted),
        Interlocked.Read(ref _dropped), Interlocked.Read(ref _invalid));
}
