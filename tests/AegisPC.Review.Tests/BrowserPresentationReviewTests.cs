using AegisPC.App.ViewModels;
using AegisPC.BrowserSecurity.Browser;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Pure inventory/UI fixtures: no real profiles, native app window or browser configuration is touched.</summary>
public sealed class BrowserPresentationReviewTests
{
    /// <summary>Unavailable roots and absent roots have different explanations, and neither means a clean browser.</summary>
    [Theory]
    [InlineData(BrowserInventoryCoverage.Unknown, "incelenemedi")]
    [InlineData(BrowserInventoryCoverage.NotPresent, "bulunamadı")]
    public void NoProfilesRetainsRootCoverage(BrowserInventoryCoverage coverage, string explanation)
    {
        var scanner = new FakeScanner(Task.FromResult(new BrowserInventorySnapshot { Coverage = coverage }));
        var viewModel = new BrowserSecurityViewModel(scanner);
        Assert.Equal("Browser Defender", viewModel.PageTitle);
        Assert.Empty(viewModel.Profiles);
        Assert.False(viewModel.HasNoExtensions);
        Assert.Contains(explanation, viewModel.ProfileCoverageMessage);
        Assert.False(viewModel.IsLoading);
    }

    /// <summary>An unobserved empty profile cannot show the verified-empty-extension state.</summary>
    [Fact]
    public void UnknownProfileIsNotAnEmptyExtensionAssertion()
    {
        var scanner = new FakeScanner(Task.FromResult(new BrowserInventorySnapshot
        {
            Coverage = BrowserInventoryCoverage.Partial,
            Profiles = [new BrowserProfileInventory { Coverage = BrowserInventoryCoverage.Unknown,
                Profile = new BrowserProfile { BrowserType = BrowserType.Chrome, ProfileName = "inert" } }]
        }));
        var viewModel = new BrowserSecurityViewModel(scanner);
        Assert.NotNull(viewModel.SelectedProfile);
        Assert.False(viewModel.HasNoExtensions);
        Assert.Contains("incelenemedi", viewModel.ProfileCoverageMessage);
    }

    /// <summary>Repeated refreshes cannot start overlapping inventories or publish an older asynchronous result over a newer one.</summary>
    [Fact]
    public async Task ConcurrentRefreshIsCoalesced()
    {
        var completion = new TaskCompletionSource<BrowserInventorySnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
        var scanner = new FakeScanner(completion.Task);
        var viewModel = new BrowserSecurityViewModel(scanner);
        Assert.True(viewModel.IsLoading);
        await viewModel.LoadBrowserDataAsync();
        Assert.Equal(1, scanner.Calls);
        completion.SetResult(new() { Coverage = BrowserInventoryCoverage.Unknown });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        while (viewModel.IsLoading) await Task.Delay(10, timeout.Token);
        Assert.Contains("incelenemedi", viewModel.ProfileCoverageMessage);
        Assert.False(viewModel.HasNoExtensions);
    }

    /// <summary>A readable selected profile must not hide a different root that could not be inventoried.</summary>
    [Fact]
    public void CompleteProfileDoesNotEraseAggregateRootGap()
    {
        var scanner = new FakeScanner(Task.FromResult(new BrowserInventorySnapshot
        {
            Coverage = BrowserInventoryCoverage.Partial,
            Issues = [new BrowserInventoryIssue { Code = "MetadataRootUnavailable" }],
            Profiles = [new BrowserProfileInventory { Coverage = BrowserInventoryCoverage.Complete,
                Profile = new BrowserProfile { BrowserType = BrowserType.Chrome, ProfileName = "inert",
                    MetadataCoverage = BrowserMetadataCoverage.Complete } }]
        }));
        var viewModel = new BrowserSecurityViewModel(scanner);
        Assert.NotNull(viewModel.SelectedProfile);
        Assert.True(viewModel.HasNoExtensions); // This individual profile's supported metadata really is empty.
        Assert.Contains("Genel kapsam: kısmi", viewModel.InventoryCoverageMessage);
        Assert.Contains("metaverisi incelendi", viewModel.ProfileCoverageMessage);
    }

    private sealed class FakeScanner(Task<BrowserInventorySnapshot> result) : IBrowserInventoryScanner
    {
        internal int Calls { get; private set; }
        /// <inheritdoc />
        public Task<BrowserInventorySnapshot> ScanInventoryAsync(CancellationToken cancellationToken = default)
        { Calls++; return result; }
        /// <inheritdoc />
        public Task<List<BrowserProfile>> ScanAllBrowsersAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("The UI must consume typed root coverage rather than discard it.");
        /// <inheritdoc />
        public Task<BrowserProfile?> ScanBrowserAsync(BrowserType browserType, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("The UI must consume the single inventory snapshot.");
    }
}
