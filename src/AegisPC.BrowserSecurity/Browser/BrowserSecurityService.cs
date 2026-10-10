using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.BrowserSecurity.Browser;

/// <summary>Coordinates metadata-only Browser Defender inventory with explicit authorization roots and coverage gaps.</summary>
public sealed class BrowserSecurityService : IBrowserInventoryScanner
{
    private readonly ILogger<BrowserSecurityService>? _logger;
    private readonly IBrowserProfileResolver _resolver;
    private BrowserInventorySnapshot _lastSnapshot = new() { Coverage = BrowserInventoryCoverage.Unknown };

    /// <summary>Creates an inventory coordinator; services must supply authorized user roots instead of enumerating all accounts.</summary>
    public BrowserSecurityService(ILogger<BrowserSecurityService>? logger = null, IBrowserProfileResolver? resolver = null)
    {
        _logger = logger;
        _resolver = resolver ?? new CurrentUserBrowserProfileResolver();
    }

    /// <summary>Gets the last completed inventory; unknown before observation and never a guarantee against cookie theft.</summary>
    public BrowserInventorySnapshot LastSnapshot => Volatile.Read(ref _lastSnapshot);

    /// <summary>Returns real profile rows for compatibility; detailed callers should use <see cref="ScanInventoryAsync"/>.</summary>
    public async Task<List<BrowserProfile>> ScanAllBrowsersAsync(CancellationToken cancellationToken = default) =>
        (await ScanInventoryAsync(cancellationToken).ConfigureAwait(false)).Profiles.Select(item => item.Profile).ToList();

    /// <summary>Inventories authorized roots with cancellation and bounded outputs; no fictitious clean profile is returned.</summary>
    public Task<BrowserInventorySnapshot> ScanInventoryAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => Inventory(cancellationToken), cancellationToken);

    /// <summary>Gets the first observed real profile of the requested browser, or null when none could be observed.</summary>
    public async Task<BrowserProfile?> ScanBrowserAsync(BrowserType browserType, CancellationToken cancellationToken = default) =>
        (await ScanAllBrowsersAsync(cancellationToken).ConfigureAwait(false)).FirstOrDefault(item => item.BrowserType == browserType);

    private BrowserInventorySnapshot Inventory(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var profiles = new List<BrowserProfileInventory>();
        var issues = new List<BrowserInventoryIssue>();
        var anyPresent = false;
        var incomplete = false;
        var roots = _resolver.ResolveRoots();
        if (roots.Count == 0) issues.Add(new BrowserInventoryIssue { Code = "AuthorizedBrowserRootsUnavailable" });
        if (roots.Count > 32) issues.Add(new BrowserInventoryIssue { Code = "BrowserRootLimitExceeded" });
        foreach (var root in roots.Take(32).DistinctBy(item => (item.BrowserType, item.RootPath.ToUpperInvariant())))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(root.RootPath))
            { issues.Add(new BrowserInventoryIssue { Code = "InvalidBrowserRoot" }); continue; }
            var snapshot = root.BrowserType == BrowserType.Firefox
                ? FirefoxSecurityScanner.ScanInventory(root.RootPath, cancellationToken)
                : ChromiumExtensionScanner.ScanInventory(root.RootPath, root.BrowserType, cancellationToken);
            anyPresent |= snapshot.Coverage != BrowserInventoryCoverage.NotPresent;
            incomplete |= snapshot.Coverage is BrowserInventoryCoverage.Partial or BrowserInventoryCoverage.Unknown
                || snapshot.Profiles.Any(item => item.Coverage != BrowserInventoryCoverage.Complete);
            profiles.AddRange(snapshot.Profiles.Take(Math.Max(0, 256 - profiles.Count)));
            issues.AddRange(snapshot.Issues.Take(Math.Max(0, 256 - issues.Count)));
            if (profiles.Count >= 256)
            { issues.Add(new BrowserInventoryIssue { Code = "AggregateProfileLimitExceeded" }); break; }
        }
        var completed = new BrowserInventorySnapshot
        {
            Profiles = profiles.ToArray(), Issues = issues.Take(256).ToArray(),
            Coverage = incomplete || issues.Count > 0 ? profiles.Count > 0 ? BrowserInventoryCoverage.Partial : BrowserInventoryCoverage.Unknown
                : anyPresent ? BrowserInventoryCoverage.Complete : BrowserInventoryCoverage.NotPresent
        };
        Interlocked.Exchange(ref _lastSnapshot, completed);
        _logger?.LogInformation("Browser Defender metadata inventory completed: {ProfileCount} profiles, coverage {Coverage}.",
            profiles.Count, completed.Coverage);
        return completed;
    }
}
