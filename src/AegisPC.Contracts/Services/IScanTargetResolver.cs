using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

/// <summary>Resolves explicit user quick-scan scope without confusing the SYSTEM service profile with interactive users.</summary>
public interface IScanTargetResolver
{
    /// <summary>Returns read-only owner/profile/folder metadata and unresolved sources; never loads an offline registry hive.</summary>
    Task<ScanTargetResolution> ResolveAsync(CancellationToken cancellationToken = default);
}
