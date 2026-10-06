using System;
using System.IO;
using System.Collections.Generic;
using AegisPC.Contracts.Services;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using AegisPC.Service.Update;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Local, synthetic regression cases for the phase-two trust boundary.</summary>
public sealed class PhaseTwoTrustRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisPhaseTwo_" + Guid.NewGuid().ToString("N"));

    public PhaseTwoTrustRegressionTests() => Directory.CreateDirectory(_root);

    [Theory]
    [InlineData("Microsoft Hackers LLC")]
    [InlineData("Evil Microsoft Corporation")]
    [InlineData("Google LLC Evil")]
    public void PublisherSubstringDoesNotEstablishTrust(string publisher)
        => Assert.False(TrustedSoftwarePolicy.IsTrustedCommercialPublisher(publisher));

    [Theory]
    [InlineData(@"C:\Users\Public\Downloads\Steam\payload.exe")]
    [InlineData(@"C:\Program Files Evil\payload.exe")]
    [InlineData(@"C:\Users\Public\ProgramData\payload.exe")]
    public void FolderNamesDoNotEstablishTrust(string path)
        => Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(path));

    [Fact]
    public void CachedThreatSurvivesInstallFolderName()
    {
        var dir = Directory.CreateDirectory(Path.Combine(_root, "Steam")).FullName;
        var path = Path.Combine(dir, "sample.bin");
        File.WriteAllText(path, "harmless synthetic fixture");
        var info = new FileInfo(path);
        var matcher = new FileHashMatcher(new HashService(), new SignatureVerifier(), null!);
        var finding = new SecurityFinding { RiskScore = 100 };
        matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, finding);
        Assert.True(matcher.TryGetCached(path, info, false, out var result));
        Assert.Same(finding, result);
    }

    [Fact]
    public async Task SignatureVerificationHonorsCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new SignatureVerifier().VerifySignatureAsync("missing.exe", cts.Token));
    }

    [Fact]
    public void SameSizeAndTimestampChangesInvalidateCache()
    {
        var path = Path.Combine(_root, "changing.bin");
        File.WriteAllText(path, "AAAA");
        var info = new FileInfo(path);
        var originalTime = info.LastWriteTimeUtc;
        var matcher = new FileHashMatcher(new HashService(), new SignatureVerifier(), null!);
        matcher.SetCache(path, info.Length, originalTime, null);
        File.WriteAllText(path, "BBBB");
        File.SetLastWriteTimeUtc(path, originalTime);
        Assert.False(matcher.TryGetCached(path, new FileInfo(path), false, out _));
    }

    [Fact]
    public void ExplicitAllowlistVerdictMustBeReevaluatedInsteadOfCachedForever()
    {
        var path = Path.Combine(_root, "allowed.bin");
        File.WriteAllText(path, "harmless");
        var info = new FileInfo(path);
        var matcher = new FileHashMatcher(new HashService(), new SignatureVerifier(), null!);
        matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, null, null, true, false);
        Assert.False(matcher.TryGetCached(path, info, false, out _));
    }

    [Fact]
    public async Task CatalogSignedWindowsFixtureIsVerified()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var result = await new SignatureVerifier().VerifySignatureAsync(path);
        Assert.True(result.IsValid, $"Catalog trust check failed: {result.NativeTrustStatus:X8}");
        Assert.Equal(AegisPC.Core.Enums.SignatureVerificationStatus.Valid, result.VerificationStatus);
        Assert.False(string.IsNullOrWhiteSpace(result.Publisher));
    }

    [Fact]
    public async Task HashCancellationIsNotConvertedToEmptyHash()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new HashService().ComputeSha256Async("missing", cts.Token));
    }

    [Fact]
    public async Task ModifiedAuthenticodeContentIsRejected()
    {
        var source = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
        Assert.True(File.Exists(source), "The signed .NET host is required for this Windows integration test.");
        var verifier = new SignatureVerifier();
        var baseline = await verifier.VerifySignatureAsync(source);
        Assert.True(baseline.IsValid, $"Signed fixture could not be validated: {baseline.NativeTrustStatus:X8}");
        var copy = Path.Combine(_root, "modified.exe");
        var bytes = File.ReadAllBytes(source);
        int pe = BitConverter.ToInt32(bytes, 0x3c);
        int optionalSize = BitConverter.ToUInt16(bytes, pe + 20);
        int firstSection = pe + 24 + optionalSize;
        int rawOffset = BitConverter.ToInt32(bytes, firstSection + 20);
        Assert.InRange(rawOffset, 1, bytes.Length - 1);
        bytes[rawOffset] ^= 1;
        File.WriteAllBytes(copy, bytes);
        var result = await verifier.VerifySignatureAsync(copy);
        Assert.False(result.IsValid);
        Assert.Equal(AegisPC.Core.Enums.SignatureVerificationStatus.Invalid, result.VerificationStatus);
        Assert.Equal(unchecked((int)0x80096010), result.NativeTrustStatus);
    }

    [Fact]
    public async Task UnverifiedDataPackageCannotBeApplied()
    {
        var path = Path.Combine(_root, "update.bin");
        await File.WriteAllTextAsync(path, "untrusted update bytes");
        await Assert.ThrowsAnyAsync<System.Security.Cryptography.CryptographicException>(() =>
            new AutoUpdateService().ApplyUpdateAsync(path, Path.Combine(_root, "target")));
        Assert.False(Directory.Exists(Path.Combine(_root, "target")));
    }

    [Fact]
    public async Task KnownMaliciousHashOverridesExplicitAllowlistAndSignature()
    {
        const string hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        var matcher = new FileHashMatcher(new FixedHash(hash), new SignatureVerifier(), new AlwaysAllow());
        var result = await matcher.EvaluateHashAndAllowlistAsync(@"C:\Program Files\fixture.exe", CancellationToken.None);
        Assert.Equal(hash, result.sha256);
        Assert.False(result.isAllowlisted);
        Assert.False(result.isMicrosoftBypassed);
        Assert.Equal(0, matcher.CachedEntriesCount); // Hash completion is not a completed clean scan.
        var score = await new RiskScoringEngine().CalculateRiskScoreAsync(new FileAnalysisResult
        {
            SHA256 = hash, FilePath = @"C:\Program Files\fixture.exe", FileName = "fixture.exe",
            IsSigned = true, SignatureValid = true, SignaturePublisher = "Microsoft Corporation", IsKnownLocation = true
        });
        Assert.Equal(100, score.score);
        Assert.Equal(AegisPC.Core.Enums.RiskLevel.ConfirmedMalicious, score.level);
    }

    [Fact]
    public void PublisherAndLocationNeverEstablishFullTrust()
    {
        var trust = TrustedSoftwarePolicy.EvaluateTrust(@"C:\Windows\System32\fixture.exe", "Microsoft Corporation", true, true, true);
        Assert.False(trust.IsFullyTrusted);
        var unsigned = TrustedSoftwarePolicy.EvaluateTrust(@"C:\Program Files\fixture.exe", null, false, false, true);
        Assert.Equal(0, unsigned.TrustScoreDiscount);
    }

    [Fact]
    public async Task FailedRealtimeInspectionIsUnknownNotClean()
    {
        var path = Path.Combine(_root, "unreadable.exe");
        File.WriteAllText(path, "harmless fixture");
        var processor = new AegisPC.Security.RealTime.RealTimeVerdictProcessor(
            new FixedHash(string.Empty), new SignatureVerifier(), new RiskScoringEngine());
        var result = await processor.InspectFileAsync(path);
        Assert.Equal(AegisPC.Core.Enums.RealTimeVerdict.Unknown, result.Verdict);
        Assert.Equal(AegisPC.Core.Enums.RealTimePolicyAction.Observe, result.RecommendedPolicy);
    }

    [Fact]
    public async Task OsBlockedContentCannotBeAllowlisted()
    {
        var matcher = new FileHashMatcher(new FixedHash("VIRUS_INFECTED_OS_BLOCKED"), new SignatureVerifier(), new AlwaysAllow());
        var result = await matcher.EvaluateHashAndAllowlistAsync("fixture.exe", CancellationToken.None);
        Assert.False(result.isAllowlisted);
        Assert.False(result.isMicrosoftBypassed);
    }

    [Fact]
    public async Task SignedSystemLocationCannotZeroIndependentRiskEvidence()
    {
        var score = await new RiskScoringEngine().CalculateRiskScoreAsync(new FileAnalysisResult
        {
            FilePath = @"C:\Windows\System32\fixture.pdf.exe", FileName = "fixture.pdf.exe",
            IsSigned = true, SignatureValid = true, SignaturePublisher = "Microsoft Corporation",
            IsKnownLocation = true, Entropy = 7.99, IsExecutable = true
        });
        Assert.True(score.score > 0, "Publisher/path trust erased independent entropy and disguise evidence.");
    }

    private sealed class FixedHash(string hash) : IHashService
    {
        public Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken = default) => Task.FromResult(hash);
        public Task<string> ComputeSha1Async(string path, CancellationToken cancellationToken = default) => Task.FromResult(string.Empty);
    }

    private sealed class AlwaysAllow : IAllowlistService
    {
        public bool IsAllowlisted(string hash) => true;
        public bool IsPathAllowlisted(string path) => true;
        public Task<bool> IsAllowlistedAsync(string hash, CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task<bool> IsPathAllowlistedAsync(string path, CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task AddToAllowlistAsync(AllowlistEntry entry, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task RemoveFromAllowlistAsync(int id, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<List<AllowlistEntry>> GetAllowlistAsync(CancellationToken cancellationToken = default) => Task.FromResult(new List<AllowlistEntry>());
        public Task<bool> CheckHashChangedAsync(AllowlistEntry entry, CancellationToken cancellationToken = default) => Task.FromResult(false);
    }

    public void Dispose() => Directory.Delete(_root, true);
}
