namespace AegisPC.Core.Enums;

/// <summary>Software classification independent of risk, inspection coverage and intervention results.</summary>
public enum SoftwareFindingClass
{
    /// <summary>Legacy or insufficient classification metadata; always visible.</summary>
    Unclassified = 0,
    /// <summary>Authenticated optional-tool classification without independent malware evidence.</summary>
    PotentiallyUnwantedToolOnly = 1,
    /// <summary>Independent malware concern; a tool label cannot hide it.</summary>
    MalwareConcern = 2
}
