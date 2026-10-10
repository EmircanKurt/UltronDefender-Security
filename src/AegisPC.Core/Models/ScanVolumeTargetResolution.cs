namespace AegisPC.Core.Models;

/// <summary>Volume-GUID roots configured for a manual full scan; readiness does not establish trust or USB identity.</summary>
public sealed record ScanVolumeTargetResolution
{
    /// <summary>Ready local volume roots; a single volume is listed once even when it has multiple mount points.</summary>
    public string[] VolumeRoots { get; init; } = [];
    /// <summary>Path-free explanations of any volume that could not be discovered or opened.</summary>
    public string[] Limitations { get; init; } = [];
}
