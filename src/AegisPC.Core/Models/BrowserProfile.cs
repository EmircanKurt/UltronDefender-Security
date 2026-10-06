using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

/// <summary>Describes browser metadata inventory coverage, not a guarantee of malware absence.</summary>
public enum BrowserMetadataCoverage
{
    /// <summary>No reliable metadata observation has been completed.</summary>
    Unknown,
    /// <summary>Supported metadata was read within the inventory limits.</summary>
    Complete,
    /// <summary>Some metadata was read but errors, limits or unsupported analysis leave a gap.</summary>
    Partial,
    /// <summary>The explicitly requested browser root is absent.</summary>
    NotPresent
}

/// <summary>A real observed browser profile with inventory coverage independent of its extension assessments.</summary>
public class BrowserProfile
{
    /// <summary>Gets or sets the browser family whose metadata was inventoried.</summary>
    public BrowserType BrowserType { get; set; }
    /// <summary>Gets or sets the observed profile directory name, never a fabricated system browser label.</summary>
    public string ProfileName { get; set; } = string.Empty;
    /// <summary>Gets or sets the explicit profile location; it is not a trust exemption.</summary>
    public string ProfilePath { get; set; } = string.Empty;
    /// <summary>Gets or sets observed extension rows; an empty collection alone does not prove an empty or clean profile.</summary>
    public List<BrowserExtension> Extensions { get; set; } = new();
    /// <summary>Gets or sets supported inventory coverage; unknown before the profile has been read.</summary>
    public BrowserMetadataCoverage MetadataCoverage { get; set; } = BrowserMetadataCoverage.Unknown;
    /// <summary>Gets or sets non-secret diagnostic codes explaining incomplete inventory.</summary>
    public List<string> InventoryIssues { get; set; } = new();

    /// <summary>Gets the number of observed rows, not necessarily every installed extension.</summary>
    public int ExtensionCount => Extensions?.Count ?? 0;
    /// <summary>Gets whether at least one extension row was observed.</summary>
    public bool HasExtensions => ExtensionCount > 0;
    /// <summary>Gets display text that distinguishes an incomplete inventory from a verified empty metadata list.</summary>
    public string DisplayText => MetadataCoverage switch
    {
        BrowserMetadataCoverage.Unknown => $"{BrowserType} ({ProfileName}) — Eklenti listesi incelenemedi",
        BrowserMetadataCoverage.Partial => $"{BrowserType} ({ProfileName}) — {ExtensionCount} eklenti · Kısmi inceleme",
        BrowserMetadataCoverage.NotPresent => $"{BrowserType} ({ProfileName}) — Profil bulunamadı",
        _ => HasExtensions ? $"{BrowserType} ({ProfileName}) — {ExtensionCount} Eklenti"
            : $"{BrowserType} ({ProfileName}) — Eklenti Yok"
    };
}
