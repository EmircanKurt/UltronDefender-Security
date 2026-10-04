namespace AegisPC.Security.RealTime;

/// <summary>Samples actual filesystem arrival coverage independently of the engine's started flag.</summary>
public interface IRealTimeCoverageProvider
{
    /// <summary>Returns a lock-consistent, path-free snapshot; gaps do not become a clean verdict.</summary>
    RealTimeCoverageSnapshot CaptureCoverage();
}

/// <summary>Filesystem-only observed coverage, safe to include in aggregate status for standard users.</summary>
public sealed record RealTimeCoverageSnapshot(int WatcherCount, bool HasPersistentGap,
    bool RecoveryPending, int PendingEvents, long LostEvents);
