using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.BrowserSecurity.Browser;

internal static class ChromiumManifestReader
{
    private static readonly HashSet<string> BroadPermissions = new(StringComparer.Ordinal)
        { "<all_urls>", "http://*/*", "https://*/*", "*://*/*", "webRequestBlocking", "debugger", "nativeMessaging", "proxy" };
    private static readonly HashSet<string> SensitivePermissions = new(StringComparer.Ordinal)
        { "webRequest", "cookies", "tabs", "management", "privacy", "declarativeNetRequest" };

    internal static BrowserExtensionInventory Parse(string id, string manifestPath,
        BrowserExtensionActivation activation, BrowserMetadataReader reader)
    {
        using var document = reader.ReadJson(manifestPath, 1024 * 1024);
        if (document is null || document.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object)
        {
            if (document is not null) reader.AddIssue("InvalidManifestObject", manifestPath);
            return Unknown(id, manifestPath, activation);
        }
        var root = document.RootElement;
        var name = BrowserMetadataReader.Text(root, "name", id);
        var version = BrowserMetadataReader.Text(root, "version");
        var description = BrowserMetadataReader.Text(root, "description");
        var updateUrl = BrowserMetadataReader.Text(root, "update_url");
        var source = SourceHint(updateUrl);
        var permissions = reader.Strings(root, "permissions", manifestPath);
        permissions.AddRange(reader.Strings(root, "host_permissions", manifestPath));
        if (root.TryGetProperty("content_scripts", out var scripts))
        {
            if (scripts.ValueKind != System.Text.Json.JsonValueKind.Array)
                reader.AddIssue("ContentScriptsUnsupported", manifestPath);
            else
            {
                if (scripts.GetArrayLength() > 128) reader.AddIssue("ContentScriptLimitExceeded", manifestPath);
                foreach (var script in scripts.EnumerateArray().Take(128))
                    permissions.AddRange(reader.Strings(script, "matches", manifestPath));
            }
        }
        permissions = permissions.Distinct(StringComparer.Ordinal).ToList();
        if (permissions.Count > 512) reader.AddIssue("ManifestPermissionLimitExceeded", manifestPath);
        permissions = permissions.Take(512).ToList();
        var optional = reader.Strings(root, "optional_permissions", manifestPath);
        optional.AddRange(reader.Strings(root, "optional_host_permissions", manifestPath));
        optional = optional.Distinct(StringComparer.Ordinal).ToList();
        if (optional.Count > 512) reader.AddIssue("ManifestOptionalPermissionLimitExceeded", manifestPath);
        optional = optional.Take(512).ToList();
        var manifestVersion = root.TryGetProperty("manifest_version", out var mv) && mv.ValueKind == System.Text.Json.JsonValueKind.Number
            && mv.TryGetInt32(out var mvValue) ? mvValue : 0;
        var reasons = new List<string>();
        var score = AssessPermissions(permissions, source, reasons);
        if (activation == BrowserExtensionActivation.Unknown)
            reasons.Add("Activation metadata is unavailable; this extension is not assumed to be enabled.");
        if (source == BrowserExtensionSourceHint.Unknown)
            reasons.Add("Update source is unknown. The manifest does not establish publisher trust.");
        if (optional.Count > 0)
            reasons.Add("Optional permissions are declared; their runtime grants were not verified.");
        var validManifest = !string.IsNullOrWhiteSpace(version) && manifestVersion is 2 or 3;
        if (!validManifest) reader.AddIssue("ManifestFieldsUnsupportedOrMissing", manifestPath);
        return new BrowserExtensionInventory
        {
            Activation = activation, SourceHint = source, ManifestVersion = manifestVersion,
            OptionalPermissions = optional.Distinct(StringComparer.Ordinal).Take(512).ToArray(),
            Extension = new BrowserExtension
            {
                Id = id, Name = name.StartsWith("__MSG_", StringComparison.Ordinal) ? id : name,
                Version = version, Description = description.StartsWith("__MSG_", StringComparison.Ordinal) ? string.Empty : description,
                Permissions = permissions, IsEnabled = activation == BrowserExtensionActivation.Enabled,
                IsActivationKnown = activation != BrowserExtensionActivation.Unknown,
                IsSourceKnown = source != BrowserExtensionSourceHint.Unknown,
                OptionalPermissions = optional.Distinct(StringComparer.Ordinal).Take(512).ToList(),
                ManifestVersion = manifestVersion,
                MetadataCoverage = validManifest ? BrowserMetadataCoverage.Partial : BrowserMetadataCoverage.Unknown,
                IsSideloaded = source == BrowserExtensionSourceHint.ExternalEndpoint,
                UpdateUrl = string.IsNullOrEmpty(updateUrl) ? null : updateUrl, ManifestPath = manifestPath,
                RiskLevel = !validManifest ? RiskLevel.Unknown : score switch
                { >= 50 => RiskLevel.HighRisk, >= 30 => RiskLevel.Suspicious, >= 15 => RiskLevel.LowRisk, _ => RiskLevel.Unknown },
                RiskReasons = reasons
            }
        };
    }

    private static int AssessPermissions(IReadOnlyCollection<string> permissions,
        BrowserExtensionSourceHint source, List<string> reasons)
    {
        var score = 0;
        if (source == BrowserExtensionSourceHint.ExternalEndpoint)
        { score += 15; reasons.Add("A non-store update endpoint is declared; this is a review hint, not malware evidence."); }
        if (permissions.Any(BroadPermissions.Contains))
        { score += 35; reasons.Add("Broad declared capabilities can access or modify browser data. Legitimate tools also use these capabilities."); }
        if (permissions.Any(SensitivePermissions.Contains))
        { score += 15; reasons.Add("Sensitive declared API permissions require review; runtime grants and malicious behavior are not established."); }
        if (score == 0) reasons.Add("No supported permission review indicator was found. Package content and malware reputation were not verified.");
        return Math.Min(score, 65);
    }

    private static BrowserExtensionSourceHint SourceHint(string updateUrl)
    {
        if (string.IsNullOrWhiteSpace(updateUrl)) return BrowserExtensionSourceHint.Unknown;
        if (!Uri.TryCreate(updateUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps
            || !uri.IsDefaultPort || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
            return BrowserExtensionSourceHint.ExternalEndpoint;
        if (uri.Host.Equals("clients2.google.com", StringComparison.OrdinalIgnoreCase)
            && uri.AbsolutePath.Equals("/service/update2/crx", StringComparison.Ordinal))
            return BrowserExtensionSourceHint.ChromeStoreEndpoint;
        if (uri.Host.Equals("edge.microsoft.com", StringComparison.OrdinalIgnoreCase)
            && uri.AbsolutePath.Equals("/extensionwebstorebase/v1/crx", StringComparison.Ordinal))
            return BrowserExtensionSourceHint.EdgeStoreEndpoint;
        return BrowserExtensionSourceHint.ExternalEndpoint;
    }

    internal static BrowserExtensionInventory Unknown(string id, string path, BrowserExtensionActivation activation) => new()
    {
        Activation = activation,
        Extension = new BrowserExtension
        {
            Id = id, Name = id, ManifestPath = path, IsEnabled = activation == BrowserExtensionActivation.Enabled,
            IsActivationKnown = activation != BrowserExtensionActivation.Unknown,
            RiskLevel = RiskLevel.Unknown,
            RiskReasons = new() { "Extension metadata could not be assessed; no malware or clean verdict is available." }
        }
    };
}
