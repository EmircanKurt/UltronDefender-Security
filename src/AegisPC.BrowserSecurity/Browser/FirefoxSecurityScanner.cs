using System.Text.Json;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.BrowserSecurity.Browser;

/// <summary>Inventories Firefox addon metadata without declaring unread packages clean or reading browsing secrets.</summary>
public static class FirefoxSecurityScanner
{
    /// <summary>Reads the current user's standard Firefox profile root; custom authorized roots use <see cref="ScanInventory"/>.</summary>
    public static List<BrowserProfile> ScanFirefoxProfiles() =>
        ScanInventory(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Mozilla", "Firefox", "Profiles")).Profiles.Select(item => item.Profile).ToList();

    /// <summary>Returns metadata-only inventories for real profiles; missing or malformed addon data remains unknown.</summary>
    public static BrowserInventorySnapshot ScanInventory(string profilesPath, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var reader = new BrowserMetadataReader();
        var present = reader.ProbeDirectory(profilesPath);
        if (present != true)
            return new BrowserInventorySnapshot
            {
                Coverage = present == false ? BrowserInventoryCoverage.NotPresent : BrowserInventoryCoverage.Unknown,
                Issues = reader.Issues.ToArray()
            };
        var profiles = new List<BrowserProfileInventory>();
        foreach (var directory in reader.Directories(profilesPath, BrowserMetadataReader.MaximumProfiles))
        {
            cancellationToken.ThrowIfCancellationRequested();
            profiles.Add(ScanProfile(directory, reader, cancellationToken));
        }
        if (profiles.Count == 0) reader.AddIssue("ProfileDiscoveryIncomplete", profilesPath);
        return new BrowserInventorySnapshot
        {
            Profiles = profiles.ToArray(), Issues = reader.Issues.ToArray(),
            Coverage = profiles.Count == 0 ? BrowserInventoryCoverage.Unknown : BrowserInventoryCoverage.Partial
        };
    }

    private static BrowserProfileInventory ScanProfile(string directory, BrowserMetadataReader reader,
        CancellationToken cancellationToken)
    {
        var startIssues = reader.Issues.Count;
        var path = Path.Combine(directory, "extensions.json");
        using var document = reader.ReadJson(path);
        var extensions = new List<BrowserExtensionInventory>();
        if (document is not null && document.RootElement.ValueKind == JsonValueKind.Object
            && document.RootElement.TryGetProperty("addons", out var addons) && addons.ValueKind == JsonValueKind.Array)
        {
            foreach (var addon in addons.EnumerateArray().Take(BrowserMetadataReader.MaximumExtensions))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (addon.ValueKind != JsonValueKind.Object)
                { reader.AddIssue("InvalidFirefoxAddonObject", path); continue; }
                extensions.Add(ParseAddon(addon, path, reader));
            }
            if (addons.GetArrayLength() > BrowserMetadataReader.MaximumExtensions)
                reader.AddIssue("ExtensionLimitExceeded", path);
        }
        else if (document is not null) reader.AddIssue("InvalidFirefoxAddonInventory", path);
        if (document is not null)
            reader.AddIssue("FirefoxPackageAndPermissionAnalysisUnavailable", path);
        return new BrowserProfileInventory
        {
            Profile = new BrowserProfile
            {
                BrowserType = BrowserType.Firefox, ProfileName = Path.GetFileName(directory), ProfilePath = directory,
                Extensions = extensions.Select(item => item.Extension).ToList(),
                MetadataCoverage = document is null ? BrowserMetadataCoverage.Unknown : BrowserMetadataCoverage.Partial,
                InventoryIssues = reader.Issues.Skip(startIssues).Select(item => item.Code).Distinct(StringComparer.Ordinal).ToList()
            },
            Extensions = extensions.ToArray(), Issues = reader.Issues.Skip(startIssues).ToArray(),
            Coverage = document is null ? BrowserInventoryCoverage.Unknown : BrowserInventoryCoverage.Partial
        };
    }

    private static BrowserExtensionInventory ParseAddon(JsonElement addon, string path, BrowserMetadataReader reader)
    {
        var id = BrowserMetadataReader.Text(addon, "id");
        var locale = BrowserMetadataReader.TryObject(addon, "defaultLocale", out var foundLocale) ? foundLocale : default;
        var activation = addon.TryGetProperty("active", out var active) && active.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? active.GetBoolean() ? BrowserExtensionActivation.Enabled : BrowserExtensionActivation.Disabled
            : BrowserExtensionActivation.Unknown;
        if (activation == BrowserExtensionActivation.Unknown) reader.AddIssue("ActivationUnknown", path);
        if (string.IsNullOrWhiteSpace(id)) reader.AddIssue("FirefoxAddonIdMissing", path);
        return new BrowserExtensionInventory
        {
            Activation = activation,
            Extension = new BrowserExtension
            {
                Id = id, Name = BrowserMetadataReader.Text(locale, "name", id),
                Version = BrowserMetadataReader.Text(addon, "version"),
                Description = BrowserMetadataReader.Text(locale, "description"),
                IsEnabled = activation == BrowserExtensionActivation.Enabled,
                IsActivationKnown = activation != BrowserExtensionActivation.Unknown,
                MetadataCoverage = BrowserMetadataCoverage.Partial,
                RiskLevel = RiskLevel.Unknown,
                RiskReasons = new() { "Firefox metadata was inventoried; package content, permission grants and malware reputation were not verified." }
            }
        };
    }
}
