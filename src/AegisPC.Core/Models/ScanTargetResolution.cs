namespace AegisPC.Core.Models;

/// <summary>User quick-scan target kind, not a trust or exclusion classification.</summary>
public enum ScanDirectoryKind
{
    /// <summary>The user's resolved or explicitly marked conventional download directory.</summary>
    Downloads,
    /// <summary>The user's desktop directory, including known redirections.</summary>
    Desktop,
    /// <summary>The user's local application-data temporary directory.</summary>
    LocalTemp,
    /// <summary>The user's per-profile startup directory.</summary>
    UserStartup,
    /// <summary>Resolved user documents used by real-time/fidye observers, not an implicit quick full-document scan.</summary>
    Documents
}

/// <summary>Registered profile and current loaded-hive state. Owner SID does not replace filesystem authorization checks.</summary>
public sealed record ScanProfileTarget
{
    /// <summary>ProfileList or current-token SID, never inferred from a folder name.</summary>
    public string OwnerSid { get; init; } = string.Empty;
    /// <summary>Explicit registered/current profile path; may reside outside the OS disk.</summary>
    public string ProfilePath { get; init; } = string.Empty;
    /// <summary>True only if this user's HKU hive is already accessible; no offline hive is loaded.</summary>
    public bool IsRegistryHiveLoaded { get; init; }
}

/// <summary>One owner-associated quick-scan folder. It grants no exemption to files found there.</summary>
public sealed record ScanDirectoryTarget
{
    /// <summary>The profile SID that supplied this known-folder configuration.</summary>
    public string OwnerSid { get; init; } = string.Empty;
    /// <summary>Resolved full folder path, or a conventional fallback accompanied by a limitation.</summary>
    public string Path { get; init; } = string.Empty;
    /// <summary>Known-folder purpose used to preserve the existing quick-scan depth.</summary>
    public ScanDirectoryKind Kind { get; init; }
    /// <summary>Whether quick scan should recursively inspect this target.</summary>
    public bool Recursive { get; init; }
}

/// <summary>Immutable target scope and visibility gaps; completeness never means inspected files are clean.</summary>
public sealed class ScanTargetResolution
{
    /// <summary>Copies source collections and reports unavailable sources without widening scope by username guessing.</summary>
    public ScanTargetResolution(IEnumerable<ScanProfileTarget> profiles, IEnumerable<ScanDirectoryTarget> directoryTargets,
        bool isComplete, IEnumerable<string>? limitations = null)
    {
        Profiles = Array.AsReadOnly(profiles.ToArray());
        DirectoryTargets = Array.AsReadOnly(directoryTargets.ToArray());
        Limitations = Array.AsReadOnly((limitations ?? []).Distinct(StringComparer.Ordinal).ToArray());
        IsComplete = isComplete && Limitations.Count == 0;
    }

    /// <summary>Profiles explicitly resolved for this caller context.</summary>
    public IReadOnlyList<ScanProfileTarget> Profiles { get; }
    /// <summary>Owner-associated folder targets; caller still handles unreadable/missing/reparse entries as partial.</summary>
    public IReadOnlyList<ScanDirectoryTarget> DirectoryTargets { get; }
    /// <summary>False for unavailable inventory, unloaded registry hives or unresolved known-folder redirection.</summary>
    public bool IsComplete { get; }
    /// <summary>Non-verdict source limitations to merge into scan coverage reporting.</summary>
    public IReadOnlyList<string> Limitations { get; }
}
