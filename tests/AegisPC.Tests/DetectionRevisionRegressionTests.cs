using System.IO;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Benign local rules demonstrate that changed detection policy invalidates old clean decisions.</summary>
[Collection("SequentialDiskTests")]
public sealed class DetectionRevisionRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisRevisionReview_" + Guid.NewGuid().ToString("N"));
    public DetectionRevisionRegressionTests() => Directory.CreateDirectory(_root);

    [Fact]
    public async Task YaraReloadInvalidatesSameContentCleanCache()
    {
        var yara = new YaraEngine(Path.Combine(_root, "rules"));
        string path = Path.Combine(_root, "benign.txt");
        File.WriteAllText(path, "REALTIME_CACHE_REVIEW_MARKER");
        var info = new FileInfo(path);
        var matcher = new FileHashMatcher(new HashService(), new Unsigned(), new NoTrust());
        matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, null);
        Assert.True((await matcher.TryGetCachedAsync(path, info, CancellationToken.None)).Hit);
        File.WriteAllText(Path.Combine(yara.RulesDirectory, "benign_review.yar"), """
            rule Benign_Review_Marker
            {
                meta:
                    description = "Benign cache regression marker; not a malware claim"
                    severity = 50
                strings:
                    $marker = "REALTIME_CACHE_REVIEW_MARKER"
                condition:
                    $marker
            }
            """);
        yara.ReloadRules();
        Assert.Contains(await yara.ScanFileAsync(path), match => match.RuleName == "Benign_Review_Marker");
        Assert.False((await matcher.TryGetCachedAsync(path, info, CancellationToken.None)).Hit);
    }

    public void Dispose() => Directory.Delete(_root, true);

    private sealed class Unsigned : ISignatureVerifier
    {
        public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default)
            => Task.FromResult(new SignatureInfo());
    }
    private sealed class NoTrust : IAllowlistService
    {
        public bool IsAllowlisted(string hash) => false;
        public bool IsPathAllowlisted(string path) => false;
        public Task<bool> IsAllowlistedAsync(string hash, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<bool> IsPathAllowlistedAsync(string path, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task AddToAllowlistAsync(AllowlistEntry entry, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task RemoveFromAllowlistAsync(int id, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<List<AllowlistEntry>> GetAllowlistAsync(CancellationToken cancellationToken = default) => Task.FromResult(new List<AllowlistEntry>());
        public Task<bool> CheckHashChangedAsync(AllowlistEntry entry, CancellationToken cancellationToken = default) => Task.FromResult(false);
    }
}
