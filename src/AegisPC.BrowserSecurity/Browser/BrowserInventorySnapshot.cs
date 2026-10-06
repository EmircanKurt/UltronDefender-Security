using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Contracts.Services;

namespace AegisPC.BrowserSecurity.Browser;

/// <summary>Describes metadata inventory coverage, not whether a browser or its extensions are safe.</summary>
public enum BrowserInventoryCoverage
{
    /// <summary>All requested supported metadata was read within the inventory limits.</summary>
    Complete,
    /// <summary>Some metadata was read, but unsupported fields, errors or limits leave a gap.</summary>
    Partial,
    /// <summary>No reliable metadata assessment could be made.</summary>
    Unknown,
    /// <summary>The explicitly requested browser root is absent; no browser was fabricated.</summary>
    NotPresent
}

/// <summary>Represents the browser-declared extension state without treating missing state as enabled.</summary>
public enum BrowserExtensionActivation
{
    /// <summary>Activation metadata is missing, invalid or not understood.</summary>
    Unknown,
    /// <summary>Supported activation metadata explicitly reports the extension disabled.</summary>
    Disabled,
    /// <summary>Supported activation metadata explicitly reports the extension enabled.</summary>
    Enabled
}

/// <summary>Records a declared update endpoint; this is not publisher authentication or malware reputation.</summary>
public enum BrowserExtensionSourceHint
{
    /// <summary>No interpretable update endpoint was declared.</summary>
    Unknown,
    /// <summary>The manifest declares the exact HTTPS Chrome Web Store update endpoint.</summary>
    ChromeStoreEndpoint,
    /// <summary>The manifest declares the exact HTTPS Edge Add-ons update endpoint.</summary>
    EdgeStoreEndpoint,
    /// <summary>The declared endpoint does not match a supported store endpoint.</summary>
    ExternalEndpoint
}

/// <summary>A bounded, non-secret issue explaining incomplete inventory without including raw JSON or cookies.</summary>
public sealed record BrowserInventoryIssue
{
    /// <summary>Gets a stable diagnostic code suitable for UI and tests.</summary>
    public string Code { get; init; } = string.Empty;
    /// <summary>Gets the affected metadata path, never the content of that file.</summary>
    public string MetadataPath { get; init; } = string.Empty;
}

/// <summary>Separates extension metadata, activation and declared optional permissions from a malware verdict.</summary>
public sealed record BrowserExtensionInventory
{
    /// <summary>Gets the backwards-compatible extension assessment; permission heuristics never confirm malware.</summary>
    public BrowserExtension Extension { get; init; } = new();
    /// <summary>Gets the explicitly observed activation state, which may be unknown.</summary>
    public BrowserExtensionActivation Activation { get; init; }
    /// <summary>Gets the unverified declared update source hint.</summary>
    public BrowserExtensionSourceHint SourceHint { get; init; }
    /// <summary>Gets optional API and host permissions, which are not assumed to have been granted.</summary>
    public IReadOnlyList<string> OptionalPermissions { get; init; } = Array.Empty<string>();
    /// <summary>Gets the supported manifest version or zero when it is missing.</summary>
    public int ManifestVersion { get; init; }
}

/// <summary>Records the supported metadata coverage for one real profile, independently of extension risk.</summary>
public sealed record BrowserProfileInventory
{
    /// <summary>Gets a real discovered profile; missing metadata never creates a fictitious profile.</summary>
    public BrowserProfile Profile { get; init; } = new();
    /// <summary>Gets metadata coverage; complete inventory does not mean malware-free.</summary>
    public BrowserInventoryCoverage Coverage { get; init; }
    /// <summary>Gets extension inventories with activation and optional-permission distinctions.</summary>
    public IReadOnlyList<BrowserExtensionInventory> Extensions { get; init; } = Array.Empty<BrowserExtensionInventory>();
    /// <summary>Gets bounded diagnostics explaining the coverage gaps.</summary>
    public IReadOnlyList<BrowserInventoryIssue> Issues { get; init; } = Array.Empty<BrowserInventoryIssue>();
}

/// <summary>A single bounded metadata-only browser inventory; it makes no read-blocking or cookie-theft claim.</summary>
public sealed record BrowserInventorySnapshot
{
    /// <summary>Gets the UTC observation time, not the last time a browser was proved safe.</summary>
    public DateTimeOffset ObservedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    /// <summary>Gets combined inventory coverage including root-level failures.</summary>
    public BrowserInventoryCoverage Coverage { get; init; }
    /// <summary>Gets real profiles observed during this inventory.</summary>
    public IReadOnlyList<BrowserProfileInventory> Profiles { get; init; } = Array.Empty<BrowserProfileInventory>();
    /// <summary>Gets bounded root-level or aggregate diagnostics.</summary>
    public IReadOnlyList<BrowserInventoryIssue> Issues { get; init; } = Array.Empty<BrowserInventoryIssue>();
}

/// <summary>Names a supported browser metadata root supplied by an authorized local user/profile resolver.</summary>
public sealed record BrowserProfileRoot
{
    /// <summary>Gets the browser family whose metadata parser should be used.</summary>
    public BrowserType BrowserType { get; init; }
    /// <summary>Gets the explicit root path; it is never used as a malware trust exemption.</summary>
    public string RootPath { get; init; } = string.Empty;
}

/// <summary>Resolves browser roots without enumerating other users or reading browser secrets.</summary>
public interface IBrowserProfileResolver
{
    /// <summary>Returns authorized roots; SYSTEM requires an explicitly authorized resolver rather than a guessed user.</summary>
    IReadOnlyList<BrowserProfileRoot> ResolveRoots();
}

/// <summary>Provides per-inventory root coverage so zero discovered profiles cannot be mistaken for an empty clean browser.</summary>
public interface IBrowserInventoryScanner : IBrowserSecurityScanner
{
    /// <summary>Returns one bounded, metadata-only inventory with root/profile gaps and genuine cancellation.</summary>
    Task<BrowserInventorySnapshot> ScanInventoryAsync(CancellationToken cancellationToken = default);
}
