using System;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

public sealed class PerformanceReviewFixTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "Aegis_PerformanceReview_" + Guid.NewGuid().ToString("N"));
    public PerformanceReviewFixTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData(1, 512)]
    [InlineData(2, 2048)]
    [InlineData(4, 4096)]
    [InlineData(12, 16384)]
    [InlineData(32, 65536)]
    public void AllModes_RespectHardwareAndLeaveRamForOtherApplications(int cores, int ramMb)
    {
        foreach (var mode in Enum.GetValues<ScanResourceMode>())
        foreach (bool hdd in new[] { false, true })
        {
            var profile = ScanResourceProfile.Create(mode, hdd, cores, (long)ramMb * 1024 * 1024);
            Assert.InRange(profile.Concurrency, 1, Math.Min(64, cores <= 2 ? cores : cores * 4));
            Assert.True(profile.MaxMemoryBudgetBytes <= (long)ramMb * 1024 * 1024 * 3 / 5);
            if (hdd) Assert.InRange(profile.Concurrency, 1, Math.Min(2, cores));
        }
    }

    [Fact]
    public void MaximumMode_YieldsWhenSystemMemoryIsUnderPressure()
    {
        var profile = ScanResourceProfile.Create(ScanResourceMode.Maximum, false, 16, 32L * 1024 * 1024 * 1024, memoryPressurePercent: 95);
        Assert.Equal(1, profile.Concurrency);
        Assert.True(profile.MaxMemoryBudgetBytes <= 128L * 1024 * 1024);
    }

    [Fact]
    public void UnknownAndNetworkStorage_AreNotAssumedToBeFastSsds()
    {
        Assert.False(DiskHardwareHelper.IsSolidStateDrive(null));
        Assert.False(DiskHardwareHelper.IsSolidStateDrive(@"\\test-host.invalid\share\fixture.txt"));
    }

    [Fact]
    public async Task CacheVerification_HonorsCancellationAndDetectsSameMetadataContentChanges()
    {
        var path = Path.Combine(_root, "fixture.bin");
        await File.WriteAllTextAsync(path, "AAAA");
        var info = new FileInfo(path);
        var timestamp = info.LastWriteTimeUtc;
        var matcher = new FileHashMatcher(new HashService(), new SignatureVerifier(), null!);
        matcher.SetCache(path, info.Length, timestamp, null);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => matcher.TryGetCachedAsync(path, info, cts.Token));
        await File.WriteAllTextAsync(path, "BBBB");
        File.SetLastWriteTimeUtc(path, timestamp);
        var result = await matcher.TryGetCachedAsync(path, new FileInfo(path), CancellationToken.None);
        Assert.False(result.Hit);
        Assert.Equal(await new HashService().ComputeSha256Async(path), result.VerifiedHash, ignoreCase: true);
    }

    [Fact]
    public async Task ArchiveEntryLimit_IsReportedAsIncomplete_NotAsCleanOrMalware()
    {
        var path = Path.Combine(_root, "many.zip");
        using (var file = File.Create(path))
        using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
            for (int i = 0; i < 25001; i++) archive.CreateEntry($"fixture_{i}.txt");
        var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
        Assert.False(result.IsComplete);
        Assert.NotNull(result.CoverageLimitation);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task ArchiveCancellation_PropagatesInsteadOfReturningClean()
    {
        var path = Path.Combine(_root, "normal.zip");
        using (var file = File.Create(path))
        using (var archive = new ZipArchive(file, ZipArchiveMode.Create)) archive.CreateEntry("fixture.txt");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new ArchiveSafetyScanner().ScanArchiveAsync(path, cts.Token));
    }
}
