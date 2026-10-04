namespace AegisPC.Security.RealTime;

/// <summary>Actual ransomware listener coverage, separate from requested shield state.</summary>
public interface IRansomwareCoverageProvider
{
    /// <summary>Returns registered roots and unresolved listener/continuity errors.</summary>
    RansomwareCoverageSnapshot CaptureRansomwareCoverage();
}

/// <summary>Observed user-mode roots; does not represent Windows Controlled Folder Access enforcement.</summary>
public sealed record RansomwareCoverageSnapshot(int WatcherCount, bool HasUnresolvedGap);
