using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Core.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Optimization;

/// <summary>Serializes persistent verdict writes, invalidation and commit barriers without silently dropping work.</summary>
public partial class ScanCacheService
{
    private readonly object _cacheStateLock = new();
    private readonly SemaphoreSlim _submissionLock = new(1, 1);
    private long _cacheGeneration;
    private int _pendingInvalidations;
    private int _disposed;
    private Exception? _persistenceError;

    private enum CacheWriteKind { Verdict, Flush, Invalidate, Clear }

    private sealed record CacheWriteRequest(CacheWriteKind Kind, CachedScanVerdict? Verdict = null, string Path = "")
    {
        internal TaskCompletionSource? Completion { get; } = Kind == CacheWriteKind.Verdict
            ? null : new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private static CachedScanVerdict Snapshot(CachedScanVerdict entry) => new()
    {
        SHA256 = entry.SHA256, FilePath = entry.FilePath, FileSize = entry.FileSize,
        LastWriteTimeUtc = entry.LastWriteTimeUtc, Verdict = entry.Verdict, RecommendedPolicy = entry.RecommendedPolicy,
        RiskScore = entry.RiskScore, RiskLevel = entry.RiskLevel, Confidence = entry.Confidence,
        ThreatTitle = entry.ThreatTitle, CachedAtUtc = entry.CachedAtUtc, RuleSetVersion = entry.RuleSetVersion,
        IntelIdentity = entry.IntelIdentity, InspectionComplete = entry.InspectionComplete, PolicyBypassed = entry.PolicyBypassed,
        CoverageLimitations = [.. entry.CoverageLimitations], Evidences = [.. entry.Evidences],
        SoftwareClass = entry.SoftwareClass, HasIndependentMalwareEvidence = entry.HasIndependentMalwareEvidence,
        SoftwareClassification = entry.SoftwareClassification is not { } metadata ? null : new SoftwareClassificationMetadata
        {
            SHA256 = metadata.SHA256, SourceReference = metadata.SourceReference, IntelVersion = metadata.IntelVersion,
            Verified = metadata.Verified, ValidUntilUtc = metadata.ValidUntilUtc
        }
    };

    private async Task MutateAsync(CacheWriteKind kind, string path, CancellationToken ct)
    {
        await _submissionLock.WaitAsync(ct).ConfigureAwait(false);
        var request = new CacheWriteRequest(kind, Path: path);
        try
        {
            lock (_cacheStateLock)
            {
                _cacheGeneration++;
                _pendingInvalidations++;
                foreach (var pair in _l1Cache)
                    if (kind == CacheWriteKind.Clear || string.Equals(pair.Value.FilePath, path, StringComparison.OrdinalIgnoreCase))
                        _l1Cache.TryRemove(pair.Key, out _);
            }
            // Once accepted, a mutation must reach its receipt; cancelling only the caller cannot resurrect old data.
            await _writeChannel.Writer.WriteAsync(request).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            RecordPersistenceFailure(ex);
            lock (_cacheStateLock) _pendingInvalidations--;
            throw;
        }
        finally { _submissionLock.Release(); }
        try { await request.Completion!.Task.ConfigureAwait(false); }
        finally { lock (_cacheStateLock) _pendingInvalidations--; }
    }

    private async Task ProcessBatchWriteQueueAsync()
    {
        await foreach (var request in _writeChannel.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            if (request.Kind == CacheWriteKind.Verdict)
            {
                var batch = new List<CachedScanVerdict>(250) { request.Verdict! };
                while (batch.Count < 250 && _writeChannel.Reader.TryPeek(out var next) && next.Kind == CacheWriteKind.Verdict)
                    if (_writeChannel.Reader.TryRead(out var item)) batch.Add(item.Verdict!);
                try { await WriteBatchToSqliteAsync(batch, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) { RecordPersistenceFailure(ex); }
                continue;
            }
            try
            {
                if (request.Kind == CacheWriteKind.Flush)
                {
                    lock (_cacheStateLock)
                        if (_persistenceError != null) throw new IOException("Scan cache persistence failed; flush was not committed.", _persistenceError);
                }
                else await ApplyMutationAsync(request).ConfigureAwait(false);
                request.Completion!.TrySetResult();
            }
            catch (Exception ex)
            {
                RecordPersistenceFailure(ex);
                request.Completion!.TrySetException(new IOException("Scan cache operation was not committed.", ex));
            }
        }
    }

    private async Task ApplyMutationAsync(CacheWriteRequest request)
    {
        await _dbWriteLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync().ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = request.Kind == CacheWriteKind.Clear
                ? "DELETE FROM ScanCacheEntries;" : "DELETE FROM ScanCacheEntries WHERE FilePath = $path;";
            if (request.Kind != CacheWriteKind.Clear) command.Parameters.AddWithValue("$path", request.Path);
            await command.ExecuteNonQueryAsync().ConfigureAwait(false);
        }
        finally { _dbWriteLock.Release(); }
    }

    private void RecordPersistenceFailure(Exception error)
    {
        lock (_cacheStateLock)
        {
            _persistenceError ??= error;
            _cacheGeneration++;
            _l1Cache.Clear();
        }
        _logger?.LogError(error, "Scan cache persistence failed; cached decisions are disabled for this instance.");
    }
}
