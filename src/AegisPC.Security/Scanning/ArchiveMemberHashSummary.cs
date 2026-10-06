namespace AegisPC.Security.Scanning;

/// <summary>Bounded diagnostic hash of one fully read member; it is not a native identity or a clean-file guarantee.</summary>
public sealed record ArchiveMemberHashSummary(string MemberName, string SHA256, long ExpandedBytes);
