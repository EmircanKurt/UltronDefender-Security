namespace AegisPC.Core.Models.Devices;

/// <summary>Initial existing-content inspection, distinct from device discovery and ongoing file events.</summary>
public sealed record MediaInspectionSnapshot
{
    /// <summary>Identity of this insertion, never a reused drive letter.</summary>
    public Guid Generation { get; init; }
    /// <summary>Volume GUID path used by this job.</summary>
    public string VolumeGuid { get; init; } = string.Empty;
    /// <summary>Pending, Scanning, Completed, Partial or Cancelled; completion does not assert clean firmware.</summary>
    public string State { get; init; } = "Pending";
    /// <summary>Files for which analysis was attempted.</summary>
    public long AttemptedFiles { get; init; }
    /// <summary>Attempted files whose stability or inspection could not be confirmed.</summary>
    public long IncompleteFiles { get; init; }
    /// <summary>Bounded traversal or file-inspection limitations.</summary>
    public string[] Limitations { get; init; } = [];
}
