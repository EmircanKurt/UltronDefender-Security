using System.Globalization;
using System.Text.Json;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.BrowserSecurity.Browser;

/// <summary>Reads bounded Chromium metadata without executing extensions, reading cookies or claiming malware certainty.</summary>
public static class ChromiumExtensionScanner
{
    /// <summary>Returns real profile rows for older callers; use <see cref="ScanInventory"/> for explicit coverage and activation gaps.</summary>
    public static List<BrowserProfile> ScanChromiumProfiles(string userDataPath, BrowserType browserType) =>
        ScanInventory(userDataPath, browserType).Profiles.Select(item => item.Profile).ToList();

    /// <summary>Inventories explicit Chromium metadata roots; malformed or missing metadata remains partial or unknown.</summary>
    public static BrowserInventorySnapshot ScanInventory(string userDataPath, BrowserType browserType,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var reader = new BrowserMetadataReader();
        var present = reader.ProbeDirectory(userDataPath);
        if (present != true)
            return new BrowserInventorySnapshot
            {
                Coverage = present == false ? BrowserInventoryCoverage.NotPresent : BrowserInventoryCoverage.Unknown,
                Issues = reader.Issues.ToArray()
            };
        var directories = DiscoverProfiles(userDataPath, reader);
        var profiles = new List<BrowserProfileInventory>();
        foreach (var directory in directories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            profiles.Add(ScanProfile(directory, browserType, reader, cancellationToken));
        }
        if (directories.Count == 0) reader.AddIssue("ProfileDiscoveryIncomplete", userDataPath);
        return new BrowserInventorySnapshot
        {
            Profiles = profiles.ToArray(), Issues = reader.Issues.ToArray(),
            Coverage = profiles.Count == 0 ? BrowserInventoryCoverage.Unknown
                : reader.Issues.Count > 0 ? BrowserInventoryCoverage.Partial : BrowserInventoryCoverage.Complete
        };
    }

    private static IReadOnlyList<string> DiscoverProfiles(string root, BrowserMetadataReader reader)
    {
        if (!BrowserMetadataReader.IsOrdinaryPath(root))
        { reader.AddIssue("ReparsePointUnsupported", root); return Array.Empty<string>(); }
        var paths = new List<string>();
        var defaultPath = Path.Combine(root, "Default");
        if (Directory.Exists(defaultPath)) paths.Add(defaultPath);
        paths.AddRange(reader.Directories(root, BrowserMetadataReader.MaximumProfiles - paths.Count, "Profile *"));
        // Opera uses its user-data directory itself as the profile root.
        if (File.Exists(Path.Combine(root, "Preferences")) || Directory.Exists(Path.Combine(root, "Extensions")))
            paths.Add(root);
        var distinct = paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (distinct.Length > BrowserMetadataReader.MaximumProfiles)
            reader.AddIssue("ProfileLimitExceeded", root);
        return distinct.Take(BrowserMetadataReader.MaximumProfiles).ToArray();
    }

    private static BrowserProfileInventory ScanProfile(string profileDirectory, BrowserType browserType,
        BrowserMetadataReader reader, CancellationToken cancellationToken)
    {
        var startIssues = reader.Issues.Count;
        var startIssueCount = reader.IssueCount;
        var securePath = Path.Combine(profileDirectory, "Secure Preferences");
        var securePresent = File.Exists(securePath);
        using var secure = securePresent ? reader.ReadJson(securePath) : null;
        using var ordinary = File.Exists(Path.Combine(profileDirectory, "Preferences"))
            ? reader.ReadJson(Path.Combine(profileDirectory, "Preferences")) : null;
        if (secure is null && ordinary is null)
            reader.AddIssue("ProfilePreferencesUnavailable", profileDirectory);
        var settings = GetSettings(secure?.RootElement ?? default);
        if (securePresent && settings.ValueKind != JsonValueKind.Object)
            reader.AddIssue("SecurePreferencesUnsupported", securePath);
        if (!securePresent)
            settings = GetSettings(ordinary?.RootElement ?? default);
        var extensions = new List<BrowserExtensionInventory>();
        foreach (var directory in reader.Directories(Path.Combine(profileDirectory, "Extensions"), BrowserMetadataReader.MaximumExtensions))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var id = Path.GetFileName(directory);
            if (id.Length != 32 || id.Any(c => c is < 'a' or > 'p'))
            { reader.AddIssue("UnsupportedExtensionId", directory); continue; }
            JsonElement state = default;
            if (settings.ValueKind == JsonValueKind.Object) settings.TryGetProperty(id, out state);
            var activation = Activation(state);
            if (activation == BrowserExtensionActivation.Unknown) reader.AddIssue("ActivationUnknown", directory);
            var preferredVersion = BrowserMetadataReader.TryObject(state, "manifest", out var manifest)
                ? BrowserMetadataReader.Text(manifest, "version") : string.Empty;
            var version = SelectVersion(directory, preferredVersion, reader);
            extensions.Add(version is null ? ChromiumManifestReader.Unknown(id, directory, activation)
                : ChromiumManifestReader.Parse(id, Path.Combine(version, "manifest.json"), activation, reader));
        }
        AddUnavailablePackages(settings, extensions, profileDirectory, reader);
        var issues = reader.Issues.Skip(startIssues).ToArray();
        var incomplete = reader.IssueCount != startIssueCount;
        if (incomplete && issues.Length == 0)
            issues = [new BrowserInventoryIssue { Code = "FurtherMetadataIssuesOmitted", MetadataPath = profileDirectory }];
        var profile = new BrowserProfile
        {
            BrowserType = browserType, ProfileName = Path.GetFileName(profileDirectory), ProfilePath = profileDirectory,
            Extensions = extensions.Select(item => item.Extension).ToList(),
            MetadataCoverage = incomplete ? BrowserMetadataCoverage.Partial : BrowserMetadataCoverage.Complete,
            InventoryIssues = issues.Select(item => item.Code).Distinct(StringComparer.Ordinal).ToList()
        };
        return new BrowserProfileInventory
        {
            Profile = profile, Extensions = extensions.ToArray(), Issues = issues,
            Coverage = incomplete ? BrowserInventoryCoverage.Partial : BrowserInventoryCoverage.Complete
        };
    }

    private static JsonElement GetSettings(JsonElement root) =>
        BrowserMetadataReader.TryObject(root, "extensions", out var extensions)
        && BrowserMetadataReader.TryObject(extensions, "settings", out var settings) ? settings : default;

    private static void AddUnavailablePackages(JsonElement settings, List<BrowserExtensionInventory> extensions,
        string profileDirectory, BrowserMetadataReader reader)
    {
        if (settings.ValueKind != JsonValueKind.Object) return;
        var observed = extensions.Select(item => item.Extension.Id).ToHashSet(StringComparer.Ordinal);
        foreach (var setting in settings.EnumerateObject().Take(BrowserMetadataReader.MaximumExtensions + 1))
        {
            if (extensions.Count >= BrowserMetadataReader.MaximumExtensions)
            { reader.AddIssue("ExtensionLimitExceeded", profileDirectory); break; }
            if (observed.Contains(setting.Name)) continue;
            if (setting.Name.Length != 32 || setting.Name.Any(c => c is < 'a' or > 'p'))
            { reader.AddIssue("UnsupportedExtensionId", profileDirectory); continue; }
            reader.AddIssue("ExtensionPackageUnavailable", profileDirectory);
            extensions.Add(ChromiumManifestReader.Unknown(setting.Name, profileDirectory, Activation(setting.Value)));
        }
    }

    private static BrowserExtensionActivation Activation(JsonElement state)
    {
        if (state.ValueKind != JsonValueKind.Object || !state.TryGetProperty("state", out var value)
            || value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number))
            return BrowserExtensionActivation.Unknown;
        // Chromium Extension::State stores ENABLED=1 and DISABLED=0. Other states are not collapsed.
        return number switch { 1 => BrowserExtensionActivation.Enabled, 0 => BrowserExtensionActivation.Disabled, _ => BrowserExtensionActivation.Unknown };
    }

    private static string? SelectVersion(string directory, string preferredVersion, BrowserMetadataReader reader)
    {
        var candidates = reader.Directories(directory, BrowserMetadataReader.MaximumVersions)
            .Select(path => new { Path = path, Version = ParseVersion(Path.GetFileName(path).Split('_')[0]) })
            .Where(item => item.Version is not null).OrderByDescending(item => item.Version).ToArray();
        if (candidates.Length == 0) { reader.AddIssue("ExtensionVersionMissing", directory); return null; }
        if (preferredVersion.Length > 0)
        {
            var selected = ParseVersion(preferredVersion);
            var match = candidates.FirstOrDefault(item => item.Version == selected);
            if (match is not null) return match.Path;
            reader.AddIssue("SelectedExtensionVersionUnavailable", directory);
            return null;
        }
        return candidates[0].Path;
    }

    private static Version? ParseVersion(string text)
    {
        var parts = text.Split('.');
        if (parts.Length is < 1 or > 4) return null;
        var numbers = new int[4];
        for (var index = 0; index < parts.Length; index++)
            if (!int.TryParse(parts[index], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[index])
                || numbers[index] > 65535) return null;
        return new Version(numbers[0], numbers[1], numbers[2], numbers[3]);
    }
}
