namespace AegisPC.Core.Models;

/// <summary>Detached provenance produced only after authenticated catalog verification, not filename matching.</summary>
public sealed class SoftwareClassificationMetadata
{
    /// <summary>Hash bound to the verified classification record.</summary>
    public string SHA256 { get; set; } = string.Empty;
    /// <summary>Reviewed source reference.</summary>
    public string SourceReference { get; set; } = string.Empty;
    /// <summary>Authenticated package version.</summary>
    public string IntelVersion { get; set; } = string.Empty;
    /// <summary>Whether the trusted catalog verified the record; missing legacy values fail closed.</summary>
    public bool Verified { get; set; }
    /// <summary>Authenticated record expiry; old/expired classifications remain visible.</summary>
    public DateTime ValidUntilUtc { get; set; }
}
