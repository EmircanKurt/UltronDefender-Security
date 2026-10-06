using AegisPC.Core.Models;
using System.IO;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert injected target-resolution infrastructure tests; no real registry, Windows token or user directory is queried.</summary>
public sealed class TargetResolutionTests
{
    /// <summary>SYSTEM uses explicit registered SIDs/paths, including a non-system-volume profile location.</summary>
    [Fact]
    public async Task SystemContext_UsesExplicitRegisteredProfilesInsteadOfSystemCurrentUser()
    {
        var registered = Fixture("S-1-5-21-111-222-333-1001", @"E:\SchoolProfiles\Öğrenci", true);
        int inventoryCalls = 0;
        var resolver = new WindowsScanTargetResolver(() => true,
            () => { inventoryCalls++; return registered; }, () => throw new InvalidOperationException("SYSTEM current-user route must not run."));
        var result = await resolver.ResolveAsync();
        Assert.Equal(1, inventoryCalls);
        Assert.Equal(@"E:\SchoolProfiles\Öğrenci", result.Profiles.Single().ProfilePath);
        Assert.Equal("S-1-5-21-111-222-333-1001", result.DirectoryTargets.Single().OwnerSid);
        Assert.True(result.IsComplete);
    }

    /// <summary>Standard-user context never enumerates other users' registered profiles.</summary>
    [Fact]
    public async Task StandardContext_UsesOnlyCurrentProfileRoute()
    {
        var current = Fixture("S-1-5-21-111-222-333-1002", @"D:\CurrentUser", true);
        var resolver = new WindowsScanTargetResolver(() => false,
            () => throw new InvalidOperationException("Machine profile inventory must not run."), () => current);
        var result = await resolver.ResolveAsync();
        Assert.Single(result.Profiles);
        Assert.Equal("S-1-5-21-111-222-333-1002", result.Profiles[0].OwnerSid);
    }

    /// <summary>An unloaded user hive keeps file targets in scope but makes registry/source coverage explicitly partial.</summary>
    [Fact]
    public async Task UnloadedHive_IsVisibleAndNeverAssumedScanned()
    {
        var fixture = Fixture("S-1-5-21-111-222-333-1001", @"E:\OfflineProfile", false);
        var result = await new WindowsScanTargetResolver(() => true, () => fixture).ResolveAsync();
        Assert.False(result.IsComplete);
        Assert.False(result.Profiles.Single().IsRegistryHiveLoaded);
        Assert.Contains("UserRegistryHiveNotLoaded", result.Limitations);
        Assert.Single(result.DirectoryTargets);
    }

    /// <summary>Inventory failure does not substitute a guessed C:\Users subtree or the SYSTEM profile.</summary>
    [Fact]
    public async Task InventoryFailure_ReturnsEmptyPartialScopeWithoutGuessing()
    {
        var resolver = new WindowsScanTargetResolver(() => true,
            () => throw new UnauthorizedAccessException("fixture denied inventory"));
        var result = await resolver.ResolveAsync();
        Assert.False(result.IsComplete);
        Assert.Empty(result.Profiles);
        Assert.Empty(result.DirectoryTargets);
        Assert.Contains("UserProfileInventoryUnavailable", result.Limitations);
    }

    /// <summary>Invalid profile paths cannot turn relative input into a service-working-directory scan target.</summary>
    [Fact]
    public async Task RelativeProfileAndUnknownOwner_AreRejectedAsPartial()
    {
        var fixture = new ScanTargetResolution([new ScanProfileTarget { OwnerSid = "fixture", ProfilePath = @"relative\user", IsRegistryHiveLoaded = true }],
            [new ScanDirectoryTarget { OwnerSid = "different", Path = @"E:\Downloads", Kind = ScanDirectoryKind.Downloads }], true);
        var result = await new WindowsScanTargetResolver(() => true, () => fixture).ResolveAsync();
        Assert.False(result.IsComplete);
        Assert.Empty(result.Profiles);
        Assert.Empty(result.DirectoryTargets);
        Assert.Contains("RegisteredProfileIdentityOrPathInvalid", result.Limitations);
        Assert.Contains("UserScanTargetIdentityOrPathInvalid", result.Limitations);
    }

    /// <summary>A supplied actual known-folder redirection is preserved rather than rewritten under the profile directory.</summary>
    [Fact]
    public async Task RedirectedKnownFolder_PreservesExplicitPathAndScanDepth()
    {
        string sid = "S-1-5-21-111-222-333-1001";
        var fixture = new ScanTargetResolution([new ScanProfileTarget { OwnerSid = sid, ProfilePath = @"E:\Profiles\student", IsRegistryHiveLoaded = true }],
            [new ScanDirectoryTarget { OwnerSid = sid, Path = @"F:\SchoolWork\Desktop", Kind = ScanDirectoryKind.Desktop, Recursive = false },
             new ScanDirectoryTarget { OwnerSid = sid, Path = @"F:\Roaming\Startup", Kind = ScanDirectoryKind.UserStartup, Recursive = true }], true);
        var result = await new WindowsScanTargetResolver(() => true, () => fixture).ResolveAsync();
        Assert.Equal(@"F:\SchoolWork\Desktop", result.DirectoryTargets.Single(target => target.Kind == ScanDirectoryKind.Desktop).Path);
        Assert.True(result.DirectoryTargets.Single(target => target.Kind == ScanDirectoryKind.UserStartup).Recursive);
        Assert.True(result.IsComplete);
    }

    /// <summary>Conventional fallback paths remain visibly incomplete when exact known-folder redirection was unavailable.</summary>
    [Fact]
    public async Task ConventionalFallback_DoesNotBecomeExactOrComplete()
    {
        var basis = Fixture("S-1-5-21-111-222-333-1001", @"E:\Profiles\user", true);
        var fixture = new ScanTargetResolution(basis.Profiles, basis.DirectoryTargets, true, ["UserKnownFolderConventionalFallback"]);
        var result = await new WindowsScanTargetResolver(() => true, () => fixture).ResolveAsync();
        Assert.False(result.IsComplete);
        Assert.Contains("UserKnownFolderConventionalFallback", result.Limitations);
        Assert.Single(result.DirectoryTargets);
    }

    /// <summary>Duplicate targets do not multiply identical owner/folder inspections.</summary>
    [Fact]
    public async Task DuplicateTarget_IsCoalescedWithoutLosingOtherOwners()
    {
        var fixture = Fixture("S-1-5-21-111-222-333-1001", @"E:\Profiles\user", true);
        var duplicate = new ScanTargetResolution(fixture.Profiles,
            [fixture.DirectoryTargets[0], fixture.DirectoryTargets[0] with { Path = fixture.DirectoryTargets[0].Path.ToUpperInvariant() }], true);
        var result = await new WindowsScanTargetResolver(() => true, () => duplicate).ResolveAsync();
        Assert.Single(result.DirectoryTargets);
        Assert.True(result.IsComplete);
    }

    /// <summary>Published target collections cannot be changed through producer lists.</summary>
    [Fact]
    public void Resolution_CopiesAllProducerCollections()
    {
        var profiles = new List<ScanProfileTarget> { new() { OwnerSid = "fixture", ProfilePath = @"E:\profile" } };
        var targets = new List<ScanDirectoryTarget> { new() { OwnerSid = "fixture", Path = @"E:\profile\Downloads" } };
        var limitations = new List<string> { "fixture unavailable" };
        var resolution = new ScanTargetResolution(profiles, targets, false, limitations);
        profiles.Clear(); targets.Clear(); limitations.Clear();
        Assert.Single(resolution.Profiles);
        Assert.Single(resolution.DirectoryTargets);
        Assert.Single(resolution.Limitations);
    }

    /// <summary>Cancelled resolution does not invoke any inventory route.</summary>
    [Fact]
    public async Task CancelledResolution_DoesNotReadInventory()
    {
        int calls = 0;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var resolver = new WindowsScanTargetResolver(() => true, () => { calls++; return new([], [], true); });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => resolver.ResolveAsync(cancellation.Token));
        Assert.Equal(0, calls);
    }

    private static ScanTargetResolution Fixture(string sid, string path, bool loaded) => new(
        [new ScanProfileTarget { OwnerSid = sid, ProfilePath = path, IsRegistryHiveLoaded = loaded }],
        [new ScanDirectoryTarget { OwnerSid = sid, Path = Path.Combine(path, "Downloads"), Kind = ScanDirectoryKind.Downloads }], true);

    /// <summary>Remote redirection remains uninspected unless explicitly selected; injected inventory does no share I/O.</summary>
    [Theory]
    [InlineData(@"\\server.invalid\share\Desktop")]
    [InlineData(@"\\?\UNC\server.invalid\share\Desktop")]
    public async Task ImplicitNetworkKnownFolder_IsRemovedWithCoverageGap(string networkPath)
    {
        var basis = Fixture("S-1-5-21-111-222-333-1001", @"C:\Profiles\user", true);
        var fixture = new ScanTargetResolution(basis.Profiles,
            [basis.DirectoryTargets[0] with { Path = networkPath }], true);
        var result = await new WindowsScanTargetResolver(() => true, () => fixture).ResolveAsync();
        Assert.Empty(result.DirectoryTargets);
        Assert.False(result.IsComplete);
        Assert.Contains("ImplicitNetworkOrDeviceTargetRequiresExplicitSelection", result.Limitations);
    }
}
