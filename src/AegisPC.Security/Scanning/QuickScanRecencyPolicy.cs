using System;
using System.IO;

namespace AegisPC.Security.Scanning;

/// <summary>Selects recent quick-scan scope, not file trust; full scan is never date-filtered.</summary>
public static class QuickScanRecencyPolicy
{
    /// <summary>Includes new or modified files in the seven-day window; invalid/future timestamps are conservatively included.</summary>
    public static bool ShouldInspect(DateTime creationUtc, DateTime modifiedUtc, DateTime nowUtc)
    {
        if (creationUtc.Year < 1980 || modifiedUtc.Year < 1980 || creationUtc > nowUtc || modifiedUtc > nowUtc) return true;
        DateTime cutoff = nowUtc.AddDays(-7);
        return creationUtc >= cutoff || modifiedUtc >= cutoff;
    }
}
