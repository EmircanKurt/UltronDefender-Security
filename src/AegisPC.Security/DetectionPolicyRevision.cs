using System.Threading;

namespace AegisPC.Security;

/// <summary>
/// Tracks process-local detection policy changes so cached verdicts cannot outlive the policy that produced them.
/// This is a cache freshness token, not a persisted threat-feed version or a cross-process synchronization mechanism.
/// </summary>
public static class DetectionPolicyRevision
{
    private static long _revision;

    /// <summary>Returns the atomic freshness token to capture before beginning a file analysis.</summary>
    public static long Current => Volatile.Read(ref _revision);

    /// <summary>
    /// Advances the token after publishing a changed detection policy; scans holding an older token must not cache their results.
    /// Returns the new process-local revision without modifying existing cached entries directly.
    /// </summary>
    public static long Invalidate() => Interlocked.Increment(ref _revision);
}
