using System.IO;
using System.Text.Json;
using System.Security.Cryptography;
using AegisPC.Service.Optimization;
using AegisPC.Contracts.Caching;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Caching;
using AegisPC.Security.ThreatIntelligence;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Isolated temporary cache tests; no installed cache, registry, service or file enforcement.</summary>
public sealed class VersionedVerdictCacheReviewTests
{
    private static CachedScanVerdict Current() => new()
    {
        SHA256 = new string('A',64), FileSize = 10, LastWriteTimeUtc = DateTime.UnixEpoch,
        InspectionComplete = true, RuleSetVersion = DetectionRuleSet.Version,
        IntelIdentity = AuthoritativeThreatCatalog.CacheIdentity, Verdict = RealTimeVerdict.Clean
    };

    /// <summary>Legacy/unversioned decisions are reanalyzed, not stamped with current provenance.</summary>
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public async Task StaleOrIncompleteEntriesDoNotHit(int mutation)
    {
        var entry = Current();
        switch (mutation)
        {
            case 0: entry.RuleSetVersion = ""; break;
            case 1: entry.IntelIdentity = "old"; break;
            case 2: entry.InspectionComplete = false; break;
            case 3: entry.CoverageLimitations = ["timeout"]; break;
            case 4: entry.Verdict = RealTimeVerdict.Unknown; break;
            case 5: entry.PolicyBypassed = true; break;
        }
        var cache = new MultiLayerScanCache(Path.Combine(Path.GetTempPath(), "Ultron-VersionedCache-" + Guid.NewGuid().ToString("N")));
        await cache.SetVerdictAsync(entry);
        Assert.Null(await cache.TryGetVerdictAsync("fixture", entry.SHA256, 10, DateTime.UnixEpoch));
    }

    /// <summary>One validated envelope retains additive data through persistence; the UI preference is not cache state.</summary>
    [Fact]
    public async Task CurrentCompleteEnvelopeSurvivesReloadWithoutLosingClassification()
    {
        string root = Path.Combine(Path.GetTempPath(), "Ultron-ToolCache-" + Guid.NewGuid().ToString("N"));
        var entry = Current(); var finding = OptionalToolVisibilityReviewTests.Tool();
        entry.SoftwareClass = finding.SoftwareClass; entry.SoftwareClassification = finding.SoftwareClassification;
        var cache = new MultiLayerScanCache(root);
        await cache.SetVerdictAsync(entry); await cache.FlushAsync();
        var loaded = await new MultiLayerScanCache(root).TryGetVerdictAsync("fixture", entry.SHA256, 10, DateTime.UnixEpoch);
        Assert.NotNull(loaded); Assert.Equal(entry.SoftwareClass, loaded!.SoftwareClass);
        Assert.Equal(entry.SoftwareClassification!.IntelVersion, loaded.SoftwareClassification!.IntelVersion);
        Assert.DoesNotContain("ShowPotentiallyUnwantedToolFindings", JsonSerializer.Serialize(loaded));
    }

    /// <summary>Matching path/size/date does not authorize a stale verdict after equal-length content replacement.</summary>
    [Fact]
    public async Task ServicePathOnlyLookupHashesCurrentContents()
    {
        string root = Path.Combine(Path.GetTempPath(), "Ultron-ServiceCache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string path = Path.Combine(root, "inert.txt");
        await File.WriteAllTextAsync(path, "before");
        DateTime stamp = File.GetLastWriteTimeUtc(path);
        using var cache = new ScanCacheService(Path.Combine(root, "cache"));
        var entry = Current(); entry.FilePath = path; entry.FileSize = 6; entry.LastWriteTimeUtc = stamp;
        entry.SHA256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path)));
        await cache.SetVerdictAsync(entry);
        Assert.NotNull(await cache.TryGetFastVerdictAsync(path, 6, stamp));
        await File.WriteAllTextAsync(path, "after!"); File.SetLastWriteTimeUtc(path, stamp);
        Assert.Null(await cache.TryGetFastVerdictAsync(path, 6, stamp));
        Assert.Null(await cache.TryGetVerdictAsync(path, "", 6, stamp));
        await cache.FlushAsync();
    }
}
