using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Security;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>
/// Exercises real temporary files and managed YARA reloads without using malware samples.
/// Cache assertions verify policy freshness, not operating-system protection coverage.
/// </summary>
public sealed class CachePolicyRevisionReviewTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "Aegis_CachePolicyRevision_" + Guid.NewGuid().ToString("N"));

    /// <summary>Creates an isolated fixture directory; existing user data is not used.</summary>
    public CachePolicyRevisionReviewTests() => Directory.CreateDirectory(_root);

    /// <summary>Removes only the unique temporary fixture directory created by this test.</summary>
    public void Dispose() => Directory.Delete(_root, recursive: true);

    /// <summary>A successful new rule reload must invalidate an unchanged file's previous clean verdict.</summary>
    [Fact]
    public async Task SuccessfulYaraReload_InvalidatesPreviousCleanCache()
    {
        const string benignMarker = "cache-policy-review-benign-marker";
        var path = Path.Combine(_root, "fixture.txt");
        await File.WriteAllTextAsync(path, benignMarker);
        var engine = new YaraEngine(Path.Combine(_root, "rules"));
        Assert.Empty(await engine.ScanFileAsync(path));

        var matcher = new FileHashMatcher(new HashService(), new SignatureVerifier(), null!);
        var info = new FileInfo(path);
        matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, null);
        Assert.True((await matcher.TryGetCachedAsync(path, info, CancellationToken.None)).Hit);

        await File.WriteAllTextAsync(Path.Combine(engine.RulesDirectory, "benign-review.yar"),
            "rule Benign_Cache_Review {\nstrings:\n$a = \"" + benignMarker + "\"\ncondition:\n$a\n}");
        engine.ReloadRules();
        Assert.Contains(await engine.ScanFileAsync(path), match => match.RuleName == "Benign_Cache_Review");
        Assert.False((await matcher.TryGetCachedAsync(path, info, CancellationToken.None)).Hit);
    }

    /// <summary>An in-flight analysis cannot publish its old result under a newer detection policy.</summary>
    [Fact]
    public async Task OldCapturedRevision_CannotPublishCompletedCleanScan()
    {
        var path = Path.Combine(_root, "in-flight.txt");
        await File.WriteAllTextAsync(path, "benign in-flight cache fixture");
        var info = new FileInfo(path);
        IFileHashMatcher matcher = new FileHashMatcher(new HashService(), new SignatureVerifier(), null!);
        long capturedRevision = DetectionPolicyRevision.Current;
        DetectionPolicyRevision.Invalidate();

        matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, null, null, false, false, capturedRevision);

        Assert.Equal(0, matcher.CachedEntriesCount);
        Assert.False((await matcher.TryGetCachedAsync(path, info, CancellationToken.None)).Hit);
    }

    /// <summary>The compatible revision-aware interface retains content-verified cache hits for a current policy.</summary>
    [Fact]
    public async Task CurrentRevision_CanPublishContentVerifiedCleanCache()
    {
        var path = Path.Combine(_root, "current.txt");
        await File.WriteAllTextAsync(path, "benign current cache fixture");
        var info = new FileInfo(path);
        IFileHashMatcher matcher = new FileHashMatcher(new HashService(), new SignatureVerifier(), null!);
        string hash = await new HashService().ComputeSha256Async(path);

        matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, null, hash, false, false, DetectionPolicyRevision.Current);

        var result = await matcher.TryGetCachedAsync(path, info, CancellationToken.None);
        Assert.True(result.Hit);
        Assert.Equal(hash, result.VerifiedHash, ignoreCase: true);
    }

    /// <summary>A reload that cannot access its directory preserves the last valid rules and cache revision.</summary>
    [Fact]
    public async Task MissingRulesDirectory_PreservesPreviousPolicyAndCache()
    {
        var engine = new YaraEngine(Path.Combine(_root, "unavailable-rules"));
        var path = Path.Combine(_root, "unchanged.txt");
        await File.WriteAllTextAsync(path, "benign unchanged policy fixture");
        var info = new FileInfo(path);
        var matcher = new FileHashMatcher(new HashService(), new SignatureVerifier(), null!);
        matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, null);
        long revision = DetectionPolicyRevision.Current;
        int ruleCount = engine.LoadedRuleCount;
        Directory.Delete(engine.RulesDirectory, recursive: true);

        engine.ReloadRules();

        Assert.Equal(revision, DetectionPolicyRevision.Current);
        Assert.Equal(ruleCount, engine.LoadedRuleCount);
        Assert.True((await matcher.TryGetCachedAsync(path, info, CancellationToken.None)).Hit);
    }

    /// <summary>Legacy nonempty findings cannot be stamped with the current rules merely by entering a new matcher.</summary>
    [Fact]
    public async Task LegacyFindingMetadataCannotCertifyCurrentCache()
    {
        string path = Path.Combine(_root, "legacy.txt"); await File.WriteAllTextAsync(path, "benign legacy fixture");
        var info = new FileInfo(path);
        var matcher = new FileHashMatcher(new HashService(), new SignatureVerifier(), null!);
        matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, new AegisPC.Core.Models.SecurityFinding());
        Assert.Equal(0, matcher.CachedEntriesCount);
        Assert.False((await matcher.TryGetCachedAsync(path, info, CancellationToken.None)).Hit);
    }
}
