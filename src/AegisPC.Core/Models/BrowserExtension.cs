using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

/// <summary>A browser metadata assessment; declared capabilities and update endpoints are not proof of maliciousness or trust.</summary>
public class BrowserExtension
{
    /// <summary>Gets or sets the observed extension identifier, which is not an unsourced malware signature.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Gets or sets the manifest display name; names never authorize protective actions.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Gets or sets the selected manifest version without assuming lexicographic order.</summary>
    public string Version { get; set; } = string.Empty;
    /// <summary>Gets or sets the non-secret extension description.</summary>
    public string Description { get; set; } = string.Empty;
    /// <summary>Gets or sets declared required API, host and content-script capabilities; runtime grants may differ.</summary>
    public List<string> Permissions { get; set; } = new();
    /// <summary>Gets or sets optional declared capabilities; these are never assumed granted.</summary>
    public List<string> OptionalPermissions { get; set; } = new();
    /// <summary>Gets or sets the observed manifest format version, or zero when unavailable.</summary>
    public int ManifestVersion { get; set; }
    /// <summary>Gets or sets whether supported metadata explicitly reports the extension enabled.</summary>
    public bool IsEnabled { get; set; }
    /// <summary>Gets or sets whether activation was observed; false means IsEnabled is not a reliable disabled-state assertion.</summary>
    public bool IsActivationKnown { get; set; }
    /// <summary>Gets or sets whether a non-store update endpoint is declared; this does not establish installation provenance.</summary>
    public bool IsSideloaded { get; set; }
    /// <summary>Gets or sets whether an update endpoint could be classified; it never establishes publisher authentication.</summary>
    public bool IsSourceKnown { get; set; }
    /// <summary>Gets or sets the unverified declared update endpoint; no network request is made during inventory.</summary>
    public string? UpdateUrl { get; set; }
    /// <summary>Gets or sets the inspected metadata location, not a hash-bound package identity.</summary>
    public string? ManifestPath { get; set; }
    /// <summary>Gets or sets supported metadata coverage independently of malware risk.</summary>
    public BrowserMetadataCoverage MetadataCoverage { get; set; } = BrowserMetadataCoverage.Unknown;
    /// <summary>Gets or sets review severity; metadata heuristics must never produce ConfirmedMalicious or claim malware-free content.</summary>
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Unknown;
    /// <summary>Gets or sets explanations separating observed capabilities from unverified malware allegations.</summary>
    public List<string> RiskReasons { get; set; } = new();
    /// <summary>Gets an activation label that does not disguise missing metadata as a disabled extension.</summary>
    public string ActivationLabel => !IsActivationKnown ? "Bilinmiyor" : IsEnabled ? "Etkin" : "Kapalı";
    /// <summary>Gets a declared source label; a matching endpoint is not a store verification or trust verdict.</summary>
    public string SourceLabel => !IsSourceKnown ? "Bilinmiyor" : IsSideloaded ? "Harici güncelleme adresi" : "Mağaza güncelleme adresi";
}
