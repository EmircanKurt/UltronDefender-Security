using System;

namespace AegisPC.Contracts.Services;

/// <summary>Reports actual native request observations independently of library initialization or local heuristic success.</summary>
public interface IAmsiObservationProvider
{
    /// <summary>Returns the last successfully completed native-provider scan time; null means no observed successful native scan.</summary>
    DateTime? LastNativeScanUtc { get; }
    /// <summary>Reports whether the most recently completed native attempt succeeded; local fallback/canonical matching never sets true.</summary>
    bool LastNativeRequestCompleted { get; }
}
