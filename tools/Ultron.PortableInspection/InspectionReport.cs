namespace Ultron.PortableInspection;

/// <summary>Records read-only evidence and omissions; no value grants containment or a clean-file verdict.</summary>
public sealed record InspectionReport
{
    /// <summary>Returns the manually selected path or archive member identifier.</summary>
    public string Path { get; init; } = string.Empty;
    /// <summary>Returns a hash only for a stable fully read bounded snapshot.</summary>
    public string Sha256 { get; init; } = string.Empty;
    /// <summary>Returns structural candidates independent of filename and extension.</summary>
    public string[] Formats { get; init; } = [];
    /// <summary>Returns review-only local rule matches, never verified malware authority.</summary>
    public string[] ReviewIndicators { get; init; } = [];
    /// <summary>Returns explicit unsupported, changed, denied, or budget-limited inspection details.</summary>
    public string[] Limitations { get; init; } = [];
    /// <summary>Indicates completion of the configured bounded preview checks, not absence of malware.</summary>
    public bool ChecksComplete { get; init; }
    /// <summary>Returns an honest display status; an unmatched file remains unverified.</summary>
    public string Status => ReviewIndicators.Length > 0 ? "Review required" : ChecksComplete ? "No preview indicator" : "Unknown / incomplete";
    /// <summary>Returns nested ZIP member reports; members are inspected in memory without extraction.</summary>
    public InspectionReport[] Members { get; init; } = [];
}

/// <summary>Bounds memory, expansion, entry counts and total scan work in the manual preview.</summary>
public sealed record InspectionLimits
{
    /// <summary>Caps each immutable snapshot at 16 MiB; larger input is reported incomplete.</summary>
    public int MaximumFileBytes { get; init; } = 16 * 1024 * 1024;
    /// <summary>Caps archive entries inspected without writing them to disk.</summary>
    public int MaximumArchiveEntries { get; init; } = 128;
    /// <summary>Caps cumulative expanded member bytes per outer archive; each source archive has its own budget.</summary>
    public long MaximumExpandedBytes { get; init; } = 32 * 1024 * 1024;
    /// <summary>Caps paths visited by one explicit folder scan.</summary>
    public int MaximumPaths { get; init; } = 5000;

    internal void Validate()
    {
        if (MaximumFileBytes is <= 0 or > 16 * 1024 * 1024 || MaximumArchiveEntries is <= 0 or > 128 ||
            MaximumExpandedBytes is <= 0 or > 32 * 1024 * 1024 || MaximumPaths is <= 0 or > 5000)
            throw new ArgumentOutOfRangeException(nameof(InspectionLimits), "Preview limits may reduce, but cannot exceed, the documented hard budgets.");
    }
}
