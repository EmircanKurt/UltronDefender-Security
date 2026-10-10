using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Archive;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Real temporary ZIP stream/hash fixtures, without malware, extraction or external decoder execution.</summary>
public sealed class LargeArchiveReviewTests
{
    /// <summary>A large renamed benign member is fully hashed but unperformed deep analysis remains partial.</summary>
    [Fact]
    public async Task ElevenMiBMemberIsStreamHashedButDeepCoverageRemainsPartial()
    {
        string path = Path.Combine(Path.GetTempPath(), $"ultron-benign-archive-{Guid.NewGuid():N}.data");
        try
        {
            byte[] chunk = new byte[1024 * 1024];
            new Random(12345).NextBytes(chunk);
            using var expected = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                using var member = archive.CreateEntry("image.jpg", CompressionLevel.NoCompression).Open();
                for (int index = 0; index < 11; index++) { member.Write(chunk); expected.AppendData(chunk); }
            }
            var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
            Assert.True(result.IsArchive);
            Assert.False(result.IsComplete);
            Assert.Equal(1, result.HashedMembers);
            Assert.Equal(11L * 1024 * 1024, result.HashedExpandedBytes);
            Assert.Equal(Convert.ToHexString(expected.GetHashAndReset()), Assert.Single(result.MemberHashes).SHA256);
            Assert.Contains("kısmi", result.CoverageLimitation);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    /// <summary>A missing file must not have successful completion coverage.</summary>
    [Fact]
    public async Task MissingArchiveIsNotCompleteOrClean()
    {
        var result = await new ArchiveSafetyScanner().ScanArchiveAsync(
            Path.Combine(Path.GetTempPath(), $"ultron-missing-{Guid.NewGuid():N}.zip"));
        Assert.False(result.IsComplete);
        Assert.NotNull(result.CoverageLimitation);
        Assert.Equal(0, result.HashedMembers);
    }

    /// <summary>Genuine cancellation is preserved rather than converted into a no-match result.</summary>
    [Fact]
    public async Task CallerCancellationDoesNotBecomeSuccessfulCompletion()
    {
        string path = Path.Combine(Path.GetTempPath(), $"ultron-cancel-archive-{Guid.NewGuid():N}.zip");
        try
        {
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                using var member = archive.CreateEntry("benign.bin").Open();
                member.Write(new byte[1024]);
            }
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await Assert.ThrowsAsync<OperationCanceledException>(() => new ArchiveSafetyScanner().ScanArchiveAsync(path, cancelled.Token));
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    /// <summary>Unsupported archive header candidates remain partial even under a non-archive extension.</summary>
    [Theory]
    [InlineData("526172211A07")]
    [InlineData("377ABCAF271C")]
    public async Task UnsupportedRenamedContainersAreNotComplete(string headerHex)
    {
        string path = Path.Combine(Path.GetTempPath(), $"ultron-inert-container-{Guid.NewGuid():N}.jpg");
        try
        {
            File.WriteAllBytes(path, Convert.FromHexString(headerHex));
            var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
            Assert.True(result.IsArchive);
            Assert.False(result.IsComplete);
            Assert.Contains("incelenmedi", result.CoverageLimitation);
            Assert.Empty(result.Findings);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    /// <summary>An empty file named as a ZIP is malformed content, not a successfully inspected empty ZIP structure.</summary>
    [Fact]
    public async Task EmptyZipCandidateIsPartial()
    {
        string path = Path.Combine(Path.GetTempPath(), $"ultron-empty-archive-{Guid.NewGuid():N}.zip");
        try
        {
            File.WriteAllBytes(path, Array.Empty<byte>());
            var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
            Assert.True(result.IsArchive);
            Assert.False(result.IsComplete);
            Assert.NotNull(result.CoverageLimitation);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    /// <summary>Pre-cancellation is honored even before a missing source can yield a partial coverage report.</summary>
    [Fact]
    public async Task CancelledMissingSourceStillReportsCancellation()
    {
        await Assert.ThrowsAsync<OperationCanceledException>(() => new ArchiveSafetyScanner().ScanArchiveAsync(
            Path.Combine(Path.GetTempPath(), $"ultron-missing-{Guid.NewGuid():N}.zip"), new CancellationToken(true)));
    }

    /// <summary>An aggregate compression anomaly remains a visible coverage gap without becoming a malware verdict.</summary>
    [Fact]
    public async Task AggregateCompressionRatioKeepsPartialCoverageThroughPlugin()
    {
        string path = Path.Combine(Path.GetTempPath(), $"ultron-benign-compression-{Guid.NewGuid():N}.zip");
        try
        {
            byte[] chunk = new byte[1024 * 1024];
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
                for (int entry = 0; entry < 6; entry++)
                {
                    using var member = archive.CreateEntry($"benign-{entry}.bin", CompressionLevel.Optimal).Open();
                    for (int part = 0; part < 9; part++) member.Write(chunk);
                }
            var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
            Assert.True(result.IsZipBomb);
            Assert.False(result.IsComplete);
            Assert.Equal(6, result.HashedMembers);
            Assert.Equal(54L * 1024 * 1024, result.HashedExpandedBytes);
            Assert.Contains("sıkıştırma", result.CoverageLimitation);
            Assert.Empty(result.Findings);
            var context = new DetectionContext { FilePath = path };
            context.Properties["Ultron.ArchiveInspectionResult"] = result;
            Assert.Empty(await new ArchiveDetectorPlugin().EvaluateAsync(context));
            Assert.Equal(result.CoverageLimitation, Assert.Single(context.CoverageLimitations));
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    /// <summary>Successfully hashed nested content contributes its actual size and hash while retaining partial container coverage.</summary>
    [Fact]
    public async Task NestedMemberHashTelemetryIncludesSuccessfullyInspectedContent()
    {
        string path = Path.Combine(Path.GetTempPath(), $"ultron-benign-nested-hash-{Guid.NewGuid():N}.zip");
        try
        {
            byte[] content = System.Text.Encoding.UTF8.GetBytes("Inert nested hash fixture");
            using var nested = new MemoryStream();
            using (var archive = new ZipArchive(nested, ZipArchiveMode.Create, leaveOpen: true))
            using (var member = archive.CreateEntry("notes.txt").Open()) member.Write(content);
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            using (var member = archive.CreateEntry("inner.bin").Open()) member.Write(nested.ToArray());
            var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
            Assert.False(result.IsComplete);
            Assert.Equal(2, result.TotalEntries);
            Assert.Equal(2, result.HashedMembers);
            Assert.Equal(nested.Length + content.Length, result.HashedExpandedBytes);
            var summary = Assert.Single(result.MemberHashes, item => item.MemberName == "inner.bin -> notes.txt");
            Assert.Equal(Convert.ToHexString(SHA256.HashData(content)), summary.SHA256);
            Assert.Equal(content.Length, summary.ExpandedBytes);
            Assert.Empty(result.Findings);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    /// <summary>All successfully hashed nested members are counted while the shared diagnostic summary list remains bounded.</summary>
    [Fact]
    public async Task NestedHashTelemetrySharesOuterSummaryLimit()
    {
        string path = Path.Combine(Path.GetTempPath(), $"ultron-benign-nested-cap-{Guid.NewGuid():N}.zip");
        try
        {
            byte[] content = new byte[] { 1, 2, 3, 4 };
            using var nested = new MemoryStream();
            using (var archive = new ZipArchive(nested, ZipArchiveMode.Create, leaveOpen: true))
                for (int index = 0; index < 256; index++)
                {
                    using var member = archive.CreateEntry($"benign-{index}.bin").Open();
                    member.Write(content);
                }
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            using (var member = archive.CreateEntry("inner.bin").Open()) member.Write(nested.ToArray());
            var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
            Assert.False(result.IsComplete);
            Assert.Equal(257, result.HashedMembers);
            Assert.Equal(nested.Length + 256L * content.Length, result.HashedExpandedBytes);
            Assert.Equal(256, result.MemberHashes.Count);
            Assert.All(result.MemberHashes, item => Assert.InRange(item.MemberName.Length, 1, 512));
            Assert.Empty(result.Findings);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }
}
