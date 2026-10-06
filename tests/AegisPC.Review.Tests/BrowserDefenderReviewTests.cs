using System.IO;
using System.Text.Json;
using AegisPC.BrowserSecurity.Browser;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Exercises real parsers against inert temporary browser metadata, never installed user profiles or active browsers.</summary>
public sealed class BrowserDefenderReviewTests
{
    private const string ExtensionId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// <summary>Unsourced identifiers, including a legitimate store extension, cannot confirm malware.</summary>
    [Theory]
    [InlineData("kpiecbbilanbpkndnnllgbghppapbkgh")]
    [InlineData("fhbjgbiflinjbdggehcddcbncdddomop")]
    [InlineData("cfhdojbkjhnklbpkdaibdccddilifddb")]
    [InlineData("djflhoibgkdhkhhcedjiklpkjnoahfmg")]
    [InlineData("oboonakemofpalcgghocfoadofidjkkk")]
    public void UnsourcedIdentifiersNeverConfirmMalware(string id)
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(id, "1.0", new { permissions = new[] { "cookies", "webRequestBlocking", "<all_urls>" } });
        var extension = Assert.Single(Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles).Extensions);
        Assert.NotEqual(RiskLevel.ConfirmedMalicious, extension.Extension.RiskLevel);
        Assert.DoesNotContain(extension.Extension.RiskReasons, reason => reason.Contains("known malicious", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Missing activation and reputation remain unknown instead of fake enabled or clean.</summary>
    [Fact]
    public void MissingActivationAndReputationRemainUnknown()
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0");
        var profile = Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles);
        var extension = Assert.Single(profile.Extensions);
        Assert.Equal(BrowserExtensionActivation.Unknown, extension.Activation);
        Assert.False(extension.Extension.IsEnabled);
        Assert.False(extension.Extension.IsActivationKnown);
        Assert.Equal("Bilinmiyor", extension.Extension.ActivationLabel);
        Assert.Equal(RiskLevel.Unknown, extension.Extension.RiskLevel);
        Assert.Equal(BrowserInventoryCoverage.Partial, profile.Coverage);
    }

    /// <summary>Numeric version comparison selects 10 rather than lexicographic 9.</summary>
    [Fact]
    public void VersionSelectionUsesNumericComponents()
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "9.0");
        fixture.Extension(ExtensionId, "10.0");
        Assert.Equal("10.0", Assert.Single(Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles).Extensions).Extension.Version);
    }

    /// <summary>The browser-selected installed version takes precedence over another version left on disk.</summary>
    [Fact]
    public void SelectedVersionTakesPrecedenceOverNewestDirectory()
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "3.0");
        fixture.Extension(ExtensionId, "4.0");
        fixture.Preferences(ExtensionId, 1, "3.0");
        var extension = Assert.Single(Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles).Extensions);
        Assert.Equal("3.0", extension.Extension.Version);
        Assert.Equal(BrowserExtensionActivation.Enabled, extension.Activation);
        Assert.True(extension.Extension.IsActivationKnown);
    }

    /// <summary>An unavailable selected package must not be replaced by another on-disk package and declared assessed.</summary>
    [Fact]
    public void MissingSelectedVersionIsUnknownRatherThanAnotherPackage()
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "4.0");
        fixture.Preferences(ExtensionId, 1, "3.0");
        var profile = Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles);
        Assert.Equal(RiskLevel.Unknown, Assert.Single(profile.Extensions).Extension.RiskLevel);
        Assert.Contains(profile.Issues, issue => issue.Code == "SelectedExtensionVersionUnavailable");
    }

    /// <summary>Enabled and disabled state comes from supported preference state, not existence of a directory.</summary>
    [Theory]
    [InlineData(0, BrowserExtensionActivation.Disabled, false)]
    [InlineData(1, BrowserExtensionActivation.Enabled, true)]
    [InlineData(2, BrowserExtensionActivation.Unknown, false)]
    public void ActivationComesFromPreferences(int state, BrowserExtensionActivation expected, bool enabled)
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0");
        fixture.Preferences(ExtensionId, state);
        var extension = Assert.Single(Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles).Extensions);
        Assert.Equal(expected, extension.Activation);
        Assert.Equal(enabled, extension.Extension.IsEnabled);
    }

    /// <summary>Lookalike domains, credentials, schemes and unrelated paths cannot impersonate an official update endpoint.</summary>
    [Theory]
    [InlineData("https://google.com.attacker.invalid/update")]
    [InlineData("https://clients2.google.com.attacker.invalid/service/update2/crx")]
    [InlineData("https://clients2.google.com@attacker.invalid/service/update2/crx")]
    [InlineData("http://clients2.google.com/service/update2/crx")]
    [InlineData("https://clients2.google.com/unrelated")]
    [InlineData("https://edge.microsoft.com.attacker.invalid/extensionwebstorebase/v1/crx")]
    public void StoreSourceUsesExactHttpsOriginAndPath(string endpoint)
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0", new { update_url = endpoint });
        var extension = Assert.Single(Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles).Extensions);
        Assert.Equal(BrowserExtensionSourceHint.ExternalEndpoint, extension.SourceHint);
        Assert.True(extension.Extension.IsSideloaded);
        Assert.NotEqual(RiskLevel.ConfirmedMalicious, extension.Extension.RiskLevel);
    }

    /// <summary>Exact store endpoints are a declared hint only, not a clean or trusted-package verdict.</summary>
    [Theory]
    [InlineData("https://clients2.google.com/service/update2/crx", BrowserExtensionSourceHint.ChromeStoreEndpoint)]
    [InlineData("https://edge.microsoft.com/extensionwebstorebase/v1/crx", BrowserExtensionSourceHint.EdgeStoreEndpoint)]
    public void ExactStoreEndpointDoesNotEstablishTrust(string endpoint, BrowserExtensionSourceHint expected)
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0", new { update_url = endpoint });
        var extension = Assert.Single(Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles).Extensions);
        Assert.Equal(expected, extension.SourceHint);
        Assert.False(extension.Extension.IsSideloaded);
        Assert.True(extension.Extension.IsSourceKnown);
        Assert.Equal(RiskLevel.Unknown, extension.Extension.RiskLevel);
    }

    /// <summary>MV3 required hosts and content scripts are assessed separately from unverified optional grants.</summary>
    [Fact]
    public void Mv3PermissionsKeepOptionalCapabilitiesSeparate()
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0", new
        {
            host_permissions = new[] { "<all_urls>" }, optional_permissions = new[] { "cookies" },
            optional_host_permissions = new[] { "https://example.invalid/*" },
            content_scripts = new[] { new { matches = new[] { "https://other.invalid/*" } } }
        });
        var extension = Assert.Single(Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles).Extensions);
        Assert.Contains("<all_urls>", extension.Extension.Permissions);
        Assert.Contains("https://other.invalid/*", extension.Extension.Permissions);
        Assert.DoesNotContain("cookies", extension.Extension.Permissions);
        Assert.Contains("cookies", extension.OptionalPermissions);
        Assert.Contains("https://example.invalid/*", extension.OptionalPermissions);
        Assert.NotEqual(RiskLevel.ConfirmedMalicious, extension.Extension.RiskLevel);
    }

    /// <summary>Omitted required or optional declarations leave a visible coverage gap even when the retained metadata is benign.</summary>
    [Theory]
    [InlineData("permissions")]
    [InlineData("host_permissions")]
    [InlineData("optional_permissions")]
    [InlineData("optional_host_permissions")]
    public void PermissionArrayLimitPreservesPartialCoverage(string property)
    {
        using var fixture = new MetadataFixture();
        var declarations = Enumerable.Range(0, 512).Select(index => $"inertPermission{index}").Append("cookies").ToArray();
        fixture.Extension(ExtensionId, "1.0", new Dictionary<string, object> { [property] = declarations });
        fixture.Preferences(ExtensionId, 1, "1.0");
        var snapshot = ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome);
        var profile = Assert.Single(snapshot.Profiles);
        var extension = Assert.Single(profile.Extensions);
        Assert.Equal(BrowserInventoryCoverage.Partial, snapshot.Coverage);
        Assert.Equal(BrowserInventoryCoverage.Partial, profile.Coverage);
        Assert.Equal(BrowserMetadataCoverage.Partial, profile.Profile.MetadataCoverage);
        Assert.Contains(profile.Issues, issue => issue.Code == "ManifestStringArrayLimitExceeded");
        Assert.DoesNotContain("cookies", extension.Extension.Permissions);
        Assert.DoesNotContain("cookies", extension.OptionalPermissions);
        Assert.NotEqual(RiskLevel.ConfirmedMalicious, extension.Extension.RiskLevel);
    }

    /// <summary>The exact declaration bound does not invent missing metadata when all declared items were read.</summary>
    [Fact]
    public void ExactPermissionArrayLimitRetainsCompleteMetadataCoverage()
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0", new { permissions = Enumerable.Range(0, 512).Select(index => $"inertPermission{index}").ToArray() });
        fixture.Preferences(ExtensionId, 1, "1.0");
        var snapshot = ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome);
        var profile = Assert.Single(snapshot.Profiles);
        Assert.Equal(BrowserInventoryCoverage.Complete, snapshot.Coverage);
        Assert.Equal(BrowserInventoryCoverage.Complete, profile.Coverage);
        Assert.Equal(512, Assert.Single(profile.Extensions).Extension.Permissions.Count);
        Assert.Empty(profile.Issues);
    }

    /// <summary>Combining individually bounded declaration fields cannot hide a truncated required or optional permission list.</summary>
    [Theory]
    [InlineData(false, "ManifestPermissionLimitExceeded")]
    [InlineData(true, "ManifestOptionalPermissionLimitExceeded")]
    public void CombinedPermissionLimitPreservesPartialCoverage(bool optional, string expectedIssue)
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0", new Dictionary<string, object>
        {
            [optional ? "optional_permissions" : "permissions"] = Enumerable.Range(0, 512).Select(index => $"inertPermission{index}").ToArray(),
            [optional ? "optional_host_permissions" : "host_permissions"] = new[] { "<all_urls>" }
        });
        fixture.Preferences(ExtensionId, 1, "1.0");
        var profile = Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles);
        Assert.Equal(BrowserInventoryCoverage.Partial, profile.Coverage);
        Assert.Contains(profile.Issues, issue => issue.Code == expectedIssue);
        Assert.NotEqual(RiskLevel.ConfirmedMalicious, Assert.Single(profile.Extensions).Extension.RiskLevel);
    }

    /// <summary>Content script truncation cannot silently omit a later broad host declaration while reporting complete metadata.</summary>
    [Fact]
    public void ContentScriptLimitPreservesPartialCoverage()
    {
        using var fixture = new MetadataFixture();
        var scripts = Enumerable.Range(0, 128).Select(_ => new { matches = new[] { "https://example.invalid/*" } })
            .Append(new { matches = new[] { "<all_urls>" } }).ToArray();
        fixture.Extension(ExtensionId, "1.0", new { content_scripts = scripts });
        fixture.Preferences(ExtensionId, 1, "1.0");
        var profile = Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles);
        Assert.Equal(BrowserInventoryCoverage.Partial, profile.Coverage);
        Assert.Contains(profile.Issues, issue => issue.Code == "ContentScriptLimitExceeded");
        Assert.DoesNotContain("<all_urls>", Assert.Single(profile.Extensions).Extension.Permissions);
    }

    /// <summary>Match-array limits are diagnosed through the same bounded helper as top-level declared permissions.</summary>
    [Fact]
    public void ContentScriptMatchLimitPreservesPartialCoverage()
    {
        using var fixture = new MetadataFixture();
        var matches = Enumerable.Range(0, 512).Select(_ => "https://example.invalid/*").Append("<all_urls>").ToArray();
        fixture.Extension(ExtensionId, "1.0", new { content_scripts = new[] { new { matches } } });
        fixture.Preferences(ExtensionId, 1, "1.0");
        var profile = Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles);
        Assert.Equal(BrowserInventoryCoverage.Partial, profile.Coverage);
        Assert.Contains(profile.Issues, issue => issue.Code == "ManifestStringArrayLimitExceeded");
        Assert.DoesNotContain("<all_urls>", Assert.Single(profile.Extensions).Extension.Permissions);
    }

    /// <summary>Discarding an oversized permission string remains visible instead of reporting a fully read manifest.</summary>
    [Fact]
    public void OversizedPermissionValuePreservesPartialCoverage()
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0", new { permissions = new[] { new string('x', 2049) } });
        fixture.Preferences(ExtensionId, 1, "1.0");
        var profile = Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles);
        Assert.Equal(BrowserInventoryCoverage.Partial, profile.Coverage);
        Assert.Contains(profile.Issues, issue => issue.Code == "ManifestStringArrayItemUnsupported");
        Assert.Empty(Assert.Single(profile.Extensions).Extension.Permissions);
    }

    /// <summary>Malformed metadata must preserve an unknown extension row and explicit inventory gaps.</summary>
    [Fact]
    public void BrokenManifestIsUnknownNotSkippedClean()
    {
        using var fixture = new MetadataFixture();
        var manifest = fixture.Extension(ExtensionId, "1.0");
        File.WriteAllText(manifest, "{ broken");
        var profile = Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles);
        Assert.Equal(RiskLevel.Unknown, Assert.Single(profile.Extensions).Extension.RiskLevel);
        Assert.Equal(BrowserInventoryCoverage.Partial, profile.Coverage);
        Assert.Contains(profile.Issues, item => item.Code.StartsWith("MetadataReadFailed:", StringComparison.Ordinal));
    }

    /// <summary>Oversized manifests produce explicit partial coverage without loading arbitrary-size metadata.</summary>
    [Fact]
    public void OversizedManifestStopsAtMetadataBudget()
    {
        using var fixture = new MetadataFixture();
        var manifest = fixture.Extension(ExtensionId, "1.0");
        File.WriteAllText(manifest, new string(' ', 1024 * 1024 + 1));
        var snapshot = ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome);
        Assert.Contains(snapshot.Issues, item => item.Code == "MetadataBudgetExceeded");
        Assert.Equal(RiskLevel.Unknown, Assert.Single(Assert.Single(snapshot.Profiles).Extensions).Extension.RiskLevel);
    }

    /// <summary>Corrupt secure preference state must not fall back to potentially stale ordinary enabled state.</summary>
    [Fact]
    public void CorruptSecurePreferencesDoNotInventEnabledState()
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0");
        fixture.Preferences(ExtensionId, 1);
        File.WriteAllText(Path.Combine(fixture.Profile, "Secure Preferences"), "{ broken");
        var extension = Assert.Single(Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles).Extensions);
        Assert.Equal(BrowserExtensionActivation.Unknown, extension.Activation);
        Assert.False(extension.Extension.IsEnabled);
    }

    /// <summary>Unsupported secure schemas and missing secure state cannot reuse stale ordinary activation metadata.</summary>
    [Theory]
    [InlineData("[]")]
    [InlineData("{\"extensions\":false}")]
    [InlineData("{\"extensions\":{\"settings\":[]}}")]
    [InlineData("{\"extensions\":{\"settings\":{}}}")]
    [InlineData("{\"extensions\":{\"settings\":{\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\":{\"state\":\"1\"}}}}")]
    public void UnsupportedSecureMetadataDoesNotReuseOrdinaryEnabledState(string secureMetadata)
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0");
        fixture.Preferences(ExtensionId, 1, "1.0");
        File.WriteAllText(Path.Combine(fixture.Profile, "Secure Preferences"), secureMetadata);
        var snapshot = ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome);
        var profile = Assert.Single(snapshot.Profiles);
        var extension = Assert.Single(profile.Extensions);
        Assert.Equal(BrowserInventoryCoverage.Partial, snapshot.Coverage);
        Assert.Equal(BrowserInventoryCoverage.Partial, profile.Coverage);
        Assert.Equal(BrowserExtensionActivation.Unknown, extension.Activation);
        Assert.False(extension.Extension.IsEnabled);
        Assert.False(extension.Extension.IsActivationKnown);
        Assert.NotEmpty(profile.Issues);
    }

    /// <summary>Supported secure activation remains authoritative when ordinary preferences retain an older enabled state.</summary>
    [Fact]
    public void SupportedSecureDisabledStateOverridesOrdinaryEnabledState()
    {
        using var fixture = new MetadataFixture();
        fixture.Extension(ExtensionId, "1.0");
        fixture.Preferences(ExtensionId, 1, "1.0");
        File.WriteAllText(Path.Combine(fixture.Profile, "Secure Preferences"), JsonSerializer.Serialize(new
        { extensions = new { settings = new Dictionary<string, object> { [ExtensionId] = new { state = 0, manifest = new { version = "1.0" } } } } }));
        var profile = Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles);
        Assert.Equal(BrowserInventoryCoverage.Complete, profile.Coverage);
        var extension = Assert.Single(profile.Extensions);
        Assert.Equal(BrowserExtensionActivation.Disabled, extension.Activation);
        Assert.False(extension.Extension.IsEnabled);
        Assert.True(extension.Extension.IsActivationKnown);
    }

    /// <summary>Installed metadata referring to a missing or unpacked package remains visible without following arbitrary package paths.</summary>
    [Fact]
    public void PreferenceOnlyExtensionIsVisibleAndUnknown()
    {
        using var fixture = new MetadataFixture();
        fixture.Preferences(ExtensionId, 1);
        var profile = Assert.Single(ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome).Profiles);
        var extension = Assert.Single(profile.Extensions);
        Assert.True(extension.Extension.IsEnabled);
        Assert.Equal(RiskLevel.Unknown, extension.Extension.RiskLevel);
        Assert.Contains(profile.Issues, item => item.Code == "ExtensionPackageUnavailable");
    }

    /// <summary>Missing Firefox metadata is unknown, not a fabricated clean addon list.</summary>
    [Fact]
    public void MissingFirefoxMetadataIsUnknown()
    {
        using var fixture = new MetadataFixture();
        var profile = Assert.Single(FirefoxSecurityScanner.ScanInventory(fixture.Root).Profiles);
        Assert.Equal(BrowserInventoryCoverage.Unknown, profile.Coverage);
        Assert.Equal(BrowserMetadataCoverage.Unknown, profile.Profile.MetadataCoverage);
        Assert.DoesNotContain("Eklenti Yok", profile.Profile.DisplayText, StringComparison.Ordinal);
        Assert.Contains(profile.Issues, item => item.Code == "MetadataMissing");
    }

    /// <summary>Firefox addons with missing locale or active fields stay unknown without throwing or dropping subsequent rows.</summary>
    [Fact]
    public void FirefoxMissingLocaleAndActivationStayUnknown()
    {
        using var fixture = new MetadataFixture();
        File.WriteAllText(Path.Combine(fixture.Profile, "extensions.json"), JsonSerializer.Serialize(new
        {
            addons = new object[] { new { id = "inert@example.invalid", version = "1.0" },
                new { id = "second@example.invalid", version = "2.0", active = false } }
        }));
        var profile = Assert.Single(FirefoxSecurityScanner.ScanInventory(fixture.Root).Profiles);
        Assert.Equal(2, profile.Extensions.Count);
        Assert.All(profile.Extensions, item => Assert.Equal(RiskLevel.Unknown, item.Extension.RiskLevel));
        Assert.Equal(BrowserExtensionActivation.Unknown, profile.Extensions[0].Activation);
        Assert.Equal(BrowserExtensionActivation.Disabled, profile.Extensions[1].Activation);
        Assert.Equal(BrowserInventoryCoverage.Partial, profile.Coverage);
    }

    /// <summary>An absent requested root never creates a system Edge profile or asserts a clean browser.</summary>
    [Fact]
    public async Task AbsentRootsDoNotFabricateDefaultProfile()
    {
        using var fixture = new MetadataFixture();
        var service = new BrowserSecurityService(resolver: new FixtureResolver(Path.Combine(fixture.Root, "absent")));
        Assert.Empty(await service.ScanAllBrowsersAsync());
        Assert.Equal(BrowserInventoryCoverage.NotPresent, service.LastSnapshot.Coverage);
    }

    /// <summary>No authorized roots yields unknown inventory rather than scanning unrelated users.</summary>
    [Fact]
    public async Task NoAuthorizedRootsProduceUnknownCoverage()
    {
        var service = new BrowserSecurityService(resolver: new FixtureResolver());
        var snapshot = await service.ScanInventoryAsync();
        Assert.Empty(snapshot.Profiles);
        Assert.Equal(BrowserInventoryCoverage.Unknown, snapshot.Coverage);
        Assert.Contains(snapshot.Issues, item => item.Code == "AuthorizedBrowserRootsUnavailable");
    }

    /// <summary>Cancellation terminates inventory rather than completing an invented successful observation.</summary>
    [Fact]
    public void CancelledInventoryDoesNotComplete()
    {
        using var fixture = new MetadataFixture();
        Assert.Throws<OperationCanceledException>(() => ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome, new CancellationToken(true)));
    }

    /// <summary>The metadata-only watcher observes a manifest edit without modifying or opening a profile's cookie contents.</summary>
    [Fact]
    public async Task MetadataWatcherReportsManifestChangeWithoutCookiePayload()
    {
        using var fixture = new MetadataFixture();
        var manifest = fixture.Extension(ExtensionId, "1.0");
        var cookiePath = Path.Combine(fixture.Profile, "Cookies");
        File.WriteAllText(cookiePath, "inert-secret-must-not-be-read-or-returned");
        using var monitor = new BrowserInventoryMonitor();
        monitor.Start(new[] { new BrowserProfileRoot { BrowserType = BrowserType.Chrome, RootPath = fixture.Root } });
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var awaiting = ReadManifestChange(monitor, manifest, cancellation.Token);
        File.AppendAllText(manifest, " ");
        var change = await awaiting;
        Assert.Equal(manifest, change.MetadataPath);
        Assert.Equal(1, monitor.GetHealth().ActiveWatchers);
        Assert.Equal("inert-secret-must-not-be-read-or-returned", File.ReadAllText(cookiePath));
    }

    /// <summary>Unavailable roots create a watcher health gap instead of being reported as active coverage.</summary>
    [Fact]
    public void MissingWatcherRootIsVisibleInHealth()
    {
        using var fixture = new MetadataFixture();
        using var monitor = new BrowserInventoryMonitor();
        monitor.Start(new[] { new BrowserProfileRoot { RootPath = Path.Combine(fixture.Root, "absent") } });
        Assert.Equal(0, monitor.GetHealth().ActiveWatchers);
        Assert.True(monitor.GetHealth().RequiresReconciliation);
    }

    /// <summary>Truncating diagnostic history cannot turn later damaged profiles into complete metadata observations.</summary>
    [Fact]
    public void ExhaustedIssueHistoryPreservesPartialCoverageForLaterProfiles()
    {
        using var fixture = new MetadataFixture();
        foreach (var name in new[] { "Default", "Profile 1" })
        {
            var profile = Path.Combine(fixture.Root, name);
            Directory.CreateDirectory(profile);
            File.WriteAllText(Path.Combine(profile, "Preferences"), "{ broken");
            for (var index = 0; index < 140; index++)
                Directory.CreateDirectory(Path.Combine(profile, "Extensions", "invalid-id-" + index));
        }
        var result = ChromiumExtensionScanner.ScanInventory(fixture.Root, BrowserType.Chrome);
        Assert.Equal(128, result.Issues.Count);
        Assert.Equal(2, result.Profiles.Count);
        Assert.All(result.Profiles, profile =>
        {
            Assert.Equal(BrowserInventoryCoverage.Partial, profile.Coverage);
            Assert.Equal(BrowserMetadataCoverage.Partial, profile.Profile.MetadataCoverage);
            Assert.NotEmpty(profile.Issues);
        });
    }

    private static async Task<BrowserMetadataChange> ReadManifestChange(IBrowserInventoryMonitor monitor, string path, CancellationToken token)
    {
        await foreach (var change in monitor.ReadChangesAsync(token))
            if (change.MetadataPath == path) return change;
        throw new InvalidOperationException("The metadata watcher completed without observing the requested fixture.");
    }

    private sealed class FixtureResolver : IBrowserProfileResolver
    {
        private readonly IReadOnlyList<BrowserProfileRoot> _roots;
        internal FixtureResolver(params string[] paths) =>
            _roots = paths.Select(path => new BrowserProfileRoot { BrowserType = BrowserType.Chrome, RootPath = path }).ToArray();
        public IReadOnlyList<BrowserProfileRoot> ResolveRoots() => _roots;
    }

    private sealed class MetadataFixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "UltronBrowserReview-" + Guid.NewGuid().ToString("N"));
        internal string Profile => Path.Combine(Root, "Default");
        internal MetadataFixture() => Directory.CreateDirectory(Profile);
        internal string Extension(string id, string version, object? additional = null)
        {
            var directory = Path.Combine(Profile, "Extensions", id, version + "_0");
            Directory.CreateDirectory(directory);
            var manifest = new Dictionary<string, object> { ["name"] = "Inert review fixture", ["version"] = version, ["manifest_version"] = 3 };
            if (additional is not null)
                foreach (var item in JsonSerializer.SerializeToElement(additional).EnumerateObject()) manifest[item.Name] = item.Value;
            var path = Path.Combine(directory, "manifest.json");
            File.WriteAllText(path, JsonSerializer.Serialize(manifest));
            return path;
        }
        internal void Preferences(string id, int state, string? selectedVersion = null)
        {
            var metadata = new Dictionary<string, object> { ["state"] = state };
            if (selectedVersion is not null) metadata["manifest"] = new { version = selectedVersion };
            File.WriteAllText(Path.Combine(Profile, "Preferences"), JsonSerializer.Serialize(new
            { extensions = new { settings = new Dictionary<string, object> { [id] = metadata } } }));
        }
        public void Dispose() => Directory.Delete(Root, true);
    }
}
