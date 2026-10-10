using System.IO;
using System.Reflection;
using AegisPC.Contracts.Caching;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.ThreatIntelligence;
using AegisPC.Service.Optimization;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Cache ordering and persistence fixtures use a unique temporary database, never installed service state.</summary>
public sealed class ServiceCacheFinalAuditTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "Ultron-FinalCache-" + Guid.NewGuid().ToString("N"));

    private static CachedScanVerdict Entry() => new()
    {
        SHA256 = new string('B', 64), FilePath = "inert-fixture", FileSize = 6,
        LastWriteTimeUtc = DateTime.UnixEpoch, InspectionComplete = true,
        RuleSetVersion = DetectionRuleSet.Version, IntelIdentity = AuthoritativeThreatCatalog.CacheIdentity,
        Verdict = RealTimeVerdict.Clean
    };

    private static Task<CachedScanVerdict?> Lookup(ScanCacheService cache, CancellationToken ct = default) =>
        cache.TryGetVerdictAsync("inert-fixture", new string('B', 64), 6, DateTime.UnixEpoch, ct);

    private static SemaphoreSlim WriteLock(ScanCacheService cache) =>
        (SemaphoreSlim)typeof(ScanCacheService).GetField("_dbWriteLock", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(cache)!;

    /// <summary>A dequeued batch is not a committed batch; the flush barrier must await the transaction.</summary>
    [Fact]
    public async Task FlushWaitsForTheCommitRatherThanEmptyQueue()
    {
        using var cache = new ScanCacheService(_root);
        var writeLock = WriteLock(cache); await writeLock.WaitAsync();
        Task flush;
        try
        {
            await cache.SetVerdictAsync(Entry()); flush = cache.FlushAsync();
            await Task.Delay(150);
            Assert.False(flush.IsCompleted);
        }
        finally { writeLock.Release(); }
        await flush.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, await RowCount(cache));
    }

    /// <summary>Both content-key and path-key aliases must be invalidated.</summary>
    [Fact]
    public async Task InvalidationRemovesThePrimaryHashAlias()
    {
        using var cache = new ScanCacheService(_root);
        await cache.SetVerdictAsync(Entry()); await cache.FlushAsync();
        await cache.InvalidateAsync("inert-fixture");
        Assert.Null(await Lookup(cache)); Assert.Equal(0, await RowCount(cache));
    }

    /// <summary>A clear cannot be overtaken by an older batch already removed from the channel.</summary>
    [Fact]
    public async Task ClearCannotResurrectAnEarlierQueuedEntry()
    {
        using var cache = new ScanCacheService(_root);
        var writeLock = WriteLock(cache); await writeLock.WaitAsync();
        Task clear;
        try
        {
            await cache.SetVerdictAsync(Entry());
            clear = Task.Run(cache.Clear); await Task.Delay(150);
        }
        finally { writeLock.Release(); }
        await clear.WaitAsync(TimeSpan.FromSeconds(5)); await cache.FlushAsync();
        Assert.Null(await Lookup(cache)); Assert.Equal(0, await RowCount(cache));
    }

    /// <summary>The two scan kinds at the same root retain independent completion timestamps.</summary>
    [Fact]
    public async Task QuickAndFullHistoryDoNotOverwriteEachOther()
    {
        using var cache = new ScanCacheService(_root);
        await cache.RecordScanCompletionAsync("inert-root", ScanType.Quick, 1, 0, 1, 0, 1);
        await cache.RecordScanCompletionAsync("inert-root", ScanType.Full, 2, 0, 2, 0, 2);
        Assert.NotNull(await cache.GetLastScanTimeAsync("inert-root", ScanType.Quick));
        Assert.NotNull(await cache.GetLastScanTimeAsync("inert-root", ScanType.Full));
    }

    /// <summary>Caller mutation after submission must not rewrite an already captured verdict.</summary>
    [Fact]
    public async Task SubmittedEnvelopeIsAnIndependentSnapshot()
    {
        using var cache = new ScanCacheService(_root);
        var entry = Entry(); await cache.SetVerdictAsync(entry);
        entry.Verdict = RealTimeVerdict.ConfirmedMalicious;
        entry.Evidences.Add("later-caller-edit");
        var loaded = await Lookup(cache);
        Assert.Equal(RealTimeVerdict.Clean, loaded!.Verdict); Assert.Empty(loaded.Evidences);
        loaded.Verdict = RealTimeVerdict.ConfirmedMalicious;
        Assert.Equal(RealTimeVerdict.Clean, (await Lookup(cache))!.Verdict);
    }

    /// <summary>Cache hits must not silently discard a cancelled caller.</summary>
    [Fact]
    public async Task CancelledLookupDoesNotReturnAnL1Hit()
    {
        using var cache = new ScanCacheService(_root);
        await cache.SetVerdictAsync(Entry());
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Lookup(cache, cancellation.Token));
    }

    /// <summary>A rejected SQLite write cannot be acknowledged as a successful flush.</summary>
    [Fact]
    public async Task PersistenceFailureIsReportedByTheBarrier()
    {
        using var cache = new ScanCacheService(_root);
        await using var connection = new SqliteConnection("Data Source=" + cache.DbPath);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "CREATE TRIGGER RejectFixture BEFORE INSERT ON ScanCacheEntries BEGIN SELECT RAISE(ABORT, 'inert-fixture-rejection'); END;";
        await command.ExecuteNonQueryAsync();
        await cache.SetVerdictAsync(Entry());
        await Assert.ThrowsAsync<IOException>(() => cache.FlushAsync());
        Assert.Null(await Lookup(cache));
    }

    /// <summary>An invalidation is serialized after a blocked earlier batch and before subsequent writes.</summary>
    [Fact]
    public async Task QueuedInvalidationWaitsForEarlierWritesAndNewWriteCanFollow()
    {
        using var cache = new ScanCacheService(_root);
        var writeLock = WriteLock(cache); await writeLock.WaitAsync();
        Task invalidation;
        try
        {
            await cache.SetVerdictAsync(Entry());
            invalidation = cache.InvalidateAsync("inert-fixture"); await Task.Delay(150);
            Assert.False(invalidation.IsCompleted); Assert.Null(await Lookup(cache));
        }
        finally { writeLock.Release(); }
        await invalidation.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, await RowCount(cache));
        await cache.SetVerdictAsync(Entry()); await cache.FlushAsync();
        Assert.NotNull(await Lookup(cache)); Assert.Equal(1, await RowCount(cache));
    }

    /// <summary>Cancelling a flush waiter neither cancels nor loses already accepted writes.</summary>
    [Fact]
    public async Task CancelledBarrierDoesNotDiscardAcceptedWrites()
    {
        using var cache = new ScanCacheService(_root);
        var writeLock = WriteLock(cache); await writeLock.WaitAsync();
        try
        {
            await cache.SetVerdictAsync(Entry());
            using var cancellation = new CancellationTokenSource(50);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cache.FlushAsync(cancellation.Token));
        }
        finally { writeLock.Release(); }
        await cache.FlushAsync(); Assert.Equal(1, await RowCount(cache));
    }

    /// <summary>The composite history migration preserves an existing legacy row and subsequent separate scan kinds.</summary>
    [Fact]
    public async Task LegacyHistoryMigrationPreservesTheLastKnownRow()
    {
        using (var initial = new ScanCacheService(_root))
        {
            await using var connection = new SqliteConnection("Data Source=" + initial.DbPath);
            await connection.OpenAsync(); await using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO ScanHistory (TargetDirectory,ScanType,LastScanCompletedUtc) VALUES ('legacy-root',$type,$time);";
            command.Parameters.AddWithValue("$type", (int)ScanType.Quick);
            command.Parameters.AddWithValue("$time", DateTime.UnixEpoch.ToString("o"));
            await command.ExecuteNonQueryAsync();
        }
        using var restarted = new ScanCacheService(_root);
        Assert.Equal(DateTime.UnixEpoch, (await restarted.GetLastScanTimeAsync("legacy-root", ScanType.Quick))!.Value.ToUniversalTime());
        await restarted.RecordScanCompletionAsync("legacy-root", ScanType.Full, 1, 0, 1, 0, 1);
        Assert.NotNull(await restarted.GetLastScanTimeAsync("legacy-root", ScanType.Quick));
        Assert.NotNull(await restarted.GetLastScanTimeAsync("legacy-root", ScanType.Full));
    }

    /// <summary>Concurrent submissions followed by clear and a fresh write retain only the post-clear envelope.</summary>
    [Fact]
    public async Task ConcurrentWritesClearAndReloadRemainCausallyOrdered()
    {
        using (var cache = new ScanCacheService(_root))
        {
            await Task.WhenAll(Enumerable.Range(0, 600).Select(index =>
            {
                var entry = Entry(); entry.FilePath += index; entry.FileSize += index;
                return cache.SetVerdictAsync(entry);
            }));
            cache.Clear();
            await cache.SetVerdictAsync(Entry()); await cache.FlushAsync();
            Assert.Equal(1, await RowCount(cache));
        }
        using var restarted = new ScanCacheService(_root);
        Assert.Equal(RealTimeVerdict.Clean, (await Lookup(restarted))!.Verdict);
        Assert.Equal(1, await RowCount(restarted));
    }

    /// <summary>SQLite round-trip preserves UTC identity, and expiry is not extended by local timezone conversion.</summary>
    [Fact]
    public async Task ReloadPreservesUtcIdentityAndRejectsExpiredEnvelope()
    {
        using (var cache = new ScanCacheService(_root, customTtl: TimeSpan.FromMinutes(1)))
        {
            await cache.SetVerdictAsync(Entry()); await cache.FlushAsync();
        }
        using (var reloaded = new ScanCacheService(_root, customTtl: TimeSpan.FromMinutes(1)))
        {
            var loaded = Assert.IsType<CachedScanVerdict>(await Lookup(reloaded));
            Assert.Equal(DateTimeKind.Utc, loaded.LastWriteTimeUtc.Kind);
            var expired = Entry(); expired.CachedAtUtc = DateTime.UtcNow.AddMinutes(-2);
            await reloaded.SetVerdictAsync(expired); await reloaded.FlushAsync();
        }
        using var last = new ScanCacheService(_root, customTtl: TimeSpan.FromMinutes(1));
        Assert.Null(await Lookup(last));
    }

    private static async Task<long> RowCount(ScanCacheService cache)
    {
        await using var connection = new SqliteConnection("Data Source=" + cache.DbPath);
        await connection.OpenAsync(); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM ScanCacheEntries;";
        return (long)(await command.ExecuteScalarAsync())!;
    }

    /// <summary>Cleanup is restricted to the GUID fixture created by this instance.</summary>
    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }
}
