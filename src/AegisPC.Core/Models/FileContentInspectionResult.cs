namespace AegisPC.Core.Models;

/// <summary>Separates evidence found in inspected bytes from completion of the common detector pipeline.</summary>
public sealed record FileContentInspectionResult
{
    /// <summary>Any observed finding, including independently confirmed evidence in partially inspected content.</summary>
    public SecurityFinding? Finding { get; init; }
    /// <summary>Whether every applicable detector and the structural inspection completed within its budget.</summary>
    public bool IsComplete { get; init; }
    /// <summary>Explicit bounded explanations of inspection gaps; not evidence that omitted content is clean.</summary>
    public string[] CoverageLimitations { get; init; } = [];
}
