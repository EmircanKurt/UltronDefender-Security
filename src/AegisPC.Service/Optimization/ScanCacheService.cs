using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Core.Enums;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Optimization
{
    /// <summary>
    /// Yüksek başarımlı akıllı tarama önbellek servisi (High-Performance Intelligent Scan Cache).
    /// - İki Katmanlı Mimari: L1 Saf Bellek İçi (O(1) < 0.005 ms) + L2 SQLite WAL Disk Veritabanı
    /// - Cache Key: SHA-256 + FileSize + LastWriteTimeUtc (& FastPath FilePath)
    /// - TTL: 7 Gün (varsayılan 7 gün sonra otomatik geçersiz sayılır ve fresh scan zorunlu kılınır)
    /// - Arka plan asenkron toplu yazım (Batched Background Writer) ile sıfır disk I/O bloklaması
    /// </summary>
    public partial class ScanCacheService : IScanCacheService, IDisposable
    {
        private readonly ILogger<ScanCacheService>? _logger;
        private readonly string _dbPath;
        private readonly string _connectionString;
        private readonly TimeSpan _ttl;
        private readonly int _maxL1Entries;

        // L1 In-Memory Cache: Key -> CachedScanVerdict
        private readonly ConcurrentDictionary<string, CachedScanVerdict> _l1Cache = new(StringComparer.OrdinalIgnoreCase);

        // Background Batch Writer Channel
        private readonly Channel<CacheWriteRequest> _writeChannel;
        private readonly Task _writerTask;
        private readonly SemaphoreSlim _dbWriteLock = new(1, 1);

        public int L1Count => _l1Cache.Count;
        public string DbPath => _dbPath;
        public TimeSpan TTL => _ttl;

        public ScanCacheService(
            string? customDbDir = null,
            TimeSpan? customTtl = null,
            ILogger<ScanCacheService>? logger = null)
        {
            _logger = logger;
            _ttl = customTtl ?? TimeSpan.FromDays(7);

            string baseDir = customDbDir ?? DetermineDefaultCacheDirectory();
            if (!Directory.Exists(baseDir))
            {
                Directory.CreateDirectory(baseDir);
            }

            _dbPath = Path.Combine(baseDir, "ScanCache.db");
            _connectionString = $"Data Source={_dbPath};Cache=Shared;Mode=ReadWriteCreate;";

            // RAM miktarına göre L1 Cache kapasitesi (8 GB RAM -> ~100.000 entry)
            long ramMb = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024);
            if (ramMb <= 0) ramMb = 8192;
            _maxL1Entries = (int)Math.Clamp(ramMb * 12, 10_000, 250_000);

            InitializeDatabase();
            TightenFileAcl(_dbPath);

            // 50.000 kapasiteli arka plan yazma kanalı
            _writeChannel = Channel.CreateBounded<CacheWriteRequest>(new BoundedChannelOptions(50_000)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false
            });

            _writerTask = Task.Run(ProcessBatchWriteQueueAsync);
        }

        private static string DetermineDefaultCacheDirectory()
        {
            try
            {
                string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string sigDir = Path.Combine(programData, "UltronDefender", "cache");
                return sigDir;
            }
            catch
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "UltronDefender", "cache");
            }
        }

        private void InitializeDatabase()
        {
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    PRAGMA journal_mode = WAL;
                    PRAGMA synchronous = NORMAL;
                    PRAGMA temp_store = MEMORY;
                    PRAGMA cache_size = -32000;

                    CREATE TABLE IF NOT EXISTS ScanCacheEntries (
                        CacheKey TEXT PRIMARY KEY,
                        FastPathKey TEXT,
                        Sha256 TEXT NOT NULL COLLATE NOCASE,
                        FilePath TEXT NOT NULL COLLATE NOCASE,
                        FileSize INTEGER NOT NULL,
                        LastWriteTimeUtc TEXT NOT NULL,
                        Verdict INTEGER NOT NULL,
                        PolicyAction INTEGER NOT NULL DEFAULT 0,
                        RiskScore INTEGER NOT NULL,
                        RiskLevel INTEGER NOT NULL,
                        ThreatTitle TEXT,
                        Confidence REAL NOT NULL DEFAULT 1.0,
                        EvidencesJson TEXT,
                        CachedAtUtc TEXT NOT NULL,
                        ExpiresAtUtc TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS IX_ScanCache_FastPathKey ON ScanCacheEntries(FastPathKey);
                    CREATE INDEX IF NOT EXISTS IX_ScanCache_Sha256 ON ScanCacheEntries(Sha256);
                    CREATE INDEX IF NOT EXISTS IX_ScanCache_FilePath ON ScanCacheEntries(FilePath);
                    CREATE INDEX IF NOT EXISTS IX_ScanCache_ExpiresAt ON ScanCacheEntries(ExpiresAtUtc);

                    CREATE TABLE IF NOT EXISTS ScanHistory (
                        TargetDirectory TEXT PRIMARY KEY COLLATE NOCASE,
                        ScanType INTEGER NOT NULL,
                        LastScanCompletedUtc TEXT NOT NULL,
                        TotalFiles INTEGER NOT NULL DEFAULT 0,
                        SkippedCachedFiles INTEGER NOT NULL DEFAULT 0,
                        FreshScannedFiles INTEGER NOT NULL DEFAULT 0,
                        ThreatsFound INTEGER NOT NULL DEFAULT 0,
                        DurationMs INTEGER NOT NULL DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS ScanHistoryV2 (
                        TargetDirectory TEXT NOT NULL COLLATE NOCASE,
                        ScanType INTEGER NOT NULL,
                        LastScanCompletedUtc TEXT NOT NULL,
                        TotalFiles INTEGER NOT NULL DEFAULT 0,
                        SkippedCachedFiles INTEGER NOT NULL DEFAULT 0,
                        FreshScannedFiles INTEGER NOT NULL DEFAULT 0,
                        ThreatsFound INTEGER NOT NULL DEFAULT 0,
                        DurationMs INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (TargetDirectory, ScanType)
                    );
                    INSERT OR IGNORE INTO ScanHistoryV2 SELECT * FROM ScanHistory;
                ";
                cmd.ExecuteNonQuery();

                // Başlangıçta süresi dolmuş eski kayıtları temizle
                PurgeExpiredEntriesInternal(conn);
            }
            catch (Exception ex)
            {
                RecordPersistenceFailure(ex);
            }
        }

        public static string GenerateKey(string sha256, long fileSize, DateTime lastWriteUtc)
        {
            return $"{sha256.ToLowerInvariant()}::{fileSize}::{lastWriteUtc.Ticks}";
        }

        public static string GenerateFastPathKey(string filePath, long fileSize, DateTime lastWriteUtc)
        {
            return $"{filePath.ToLowerInvariant()}::{fileSize}::{lastWriteUtc.Ticks}";
        }

        /// <summary>
        /// Dosya için geçerli bir önbellek kaydı arar (L1 Memory -> L2 SQLite).
        /// 7 günlük TTL süresi dolmuşsa kayıt geçersiz sayılır (null döner) ve taze tarama tetiklenir.
        /// </summary>
        public async Task<CachedScanVerdict?> TryGetVerdictAsync(
            string filePath,
            string sha256,
            long fileSize,
            DateTime lastWriteUtc,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            long observedGeneration;
            lock (_cacheStateLock)
            {
                if (_pendingInvalidations != 0 || _persistenceError != null) return null;
                observedGeneration = _cacheGeneration;
            }
            if (string.IsNullOrWhiteSpace(sha256))
                return await TryGetFastVerdictAsync(filePath, fileSize, lastWriteUtc, cancellationToken);

            string key = !string.IsNullOrWhiteSpace(sha256)
                ? GenerateKey(sha256, fileSize, lastWriteUtc)
                : GenerateFastPathKey(filePath, fileSize, lastWriteUtc);

            // 1. L1 Bellek İçi Hızlı Arama (< 0.005 ms)
            lock (_cacheStateLock)
            {
                if (_pendingInvalidations != 0 || observedGeneration != _cacheGeneration || _persistenceError != null) return null;
                if (_l1Cache.TryGetValue(key, out var cached))
                {
                    if (!AegisPC.Security.Caching.ScanVerdictCachePolicy.IsCurrent(cached) || DateTime.UtcNow > cached.CachedAtUtc + _ttl)
                    {
                        _l1Cache.TryRemove(key, out _);
                        return null;
                    }
                    return Snapshot(cached);
                }
            }

            // 2. L2 SQLite Kalıcı Veritabanı Araması
            try
            {
                await using var conn = new SqliteConnection(_connectionString);
                await conn.OpenAsync(cancellationToken);

                await using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    SELECT Sha256, FilePath, FileSize, LastWriteTimeUtc, Verdict, PolicyAction, 
                           RiskScore, RiskLevel, ThreatTitle, Confidence, EvidencesJson, CachedAtUtc, ExpiresAtUtc
                    FROM ScanCacheEntries
                    WHERE CacheKey = $key OR FastPathKey = $key
                    LIMIT 1;
                ";
                cmd.Parameters.AddWithValue("$key", key);

                await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken))
                {
                    var expiresUtc = DateTime.Parse(reader.GetString(12), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
                    // TTL kontrolü
                    if (DateTime.UtcNow > expiresUtc)
                    {
                        return null; // Süresi dolmuş, fresh scan yap
                    }

                    var verdict = new CachedScanVerdict
                    {
                        SHA256 = reader.GetString(0),
                        FilePath = reader.GetString(1),
                        FileSize = reader.GetInt64(2),
                        LastWriteTimeUtc = DateTime.Parse(reader.GetString(3), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                        Verdict = (RealTimeVerdict)reader.GetInt32(4),
                        RecommendedPolicy = (RealTimePolicyAction)reader.GetInt32(5),
                        RiskScore = reader.GetInt32(6),
                        RiskLevel = (RiskLevel)reader.GetInt32(7),
                        ThreatTitle = reader.IsDBNull(8) ? string.Empty : reader.GetString(8),
                        Confidence = reader.GetDouble(9),
                        CachedAtUtc = DateTime.Parse(reader.GetString(11), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)
                    };

                    if (reader.IsDBNull(10)) return null;
                    try
                    {
                        var envelope = JsonSerializer.Deserialize<CachedScanVerdict>(reader.GetString(10));
                        if (envelope == null || !AegisPC.Security.Caching.ScanVerdictCachePolicy.IsCurrent(envelope) ||
                            envelope.SHA256 != verdict.SHA256 || envelope.FileSize != verdict.FileSize ||
                            envelope.LastWriteTimeUtc != verdict.LastWriteTimeUtc) return null;
                        verdict = envelope;
                    }
                    catch (JsonException) { return null; } // Legacy arrays are reanalyzed, not relabeled.
                    lock (_cacheStateLock)
                    {
                        if (_pendingInvalidations != 0 || observedGeneration != _cacheGeneration || _persistenceError != null) return null;
                        EnforceL1Capacity();
                        _l1Cache[key] = verdict;
                        return Snapshot(verdict);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "ScanCache lookup failed: {Key}", key);
            }

            return null;
        }

        /// <summary>
        /// Legacy path-only callers must verify current content; equal path, size and timestamp are not file identity.
        /// </summary>
        public async Task<CachedScanVerdict?> TryGetFastVerdictAsync(
            string filePath,
            long fileSize,
            DateTime lastWriteUtc,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return null;

            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await using var source = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, 81920, useAsync: true);
                if (source.Length != fileSize || File.GetLastWriteTimeUtc(filePath) != lastWriteUtc) return null;
                string verifiedHash = Convert.ToHexString(await SHA256.HashDataAsync(source, cancellationToken));
                // Keep the read lock throughout lookup; a path-only decision cannot bypass the content check.
                return await TryGetVerdictAsync(filePath, verifiedHash, fileSize, lastWriteUtc, cancellationToken);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger?.LogDebug(ex, "Path-only cache content verification failed: {Path}", filePath);
                return null;
            }
        }

        /// <summary>
        /// Tarama sonucunu önbelleğe yazar (L1 bellek + arka plan L2 SQLite kuyruğu).
        /// </summary>
        public async Task SetVerdictAsync(CachedScanVerdict verdict, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            verdict = Snapshot(verdict);
            if (!AegisPC.Security.Caching.ScanVerdictCachePolicy.IsCurrent(verdict)) return;
            if (verdict.CachedAtUtc == default)
            {
                verdict.CachedAtUtc = DateTime.UtcNow;
            }

            string primaryKey = !string.IsNullOrWhiteSpace(verdict.SHA256)
                ? GenerateKey(verdict.SHA256, verdict.FileSize, verdict.LastWriteTimeUtc)
                : GenerateFastPathKey(verdict.FilePath, verdict.FileSize, verdict.LastWriteTimeUtc);

            string fastKey = !string.IsNullOrWhiteSpace(verdict.FilePath)
                ? GenerateFastPathKey(verdict.FilePath, verdict.FileSize, verdict.LastWriteTimeUtc)
                : string.Empty;

            await _submissionLock.WaitAsync(cancellationToken);
            try
            {
                await _writeChannel.Writer.WriteAsync(new(CacheWriteKind.Verdict, verdict), cancellationToken);
                lock (_cacheStateLock)
                {
                    EnforceL1Capacity();
                    _l1Cache[primaryKey] = verdict;
                    if (!string.IsNullOrEmpty(fastKey)) _l1Cache[fastKey] = verdict;
                }
            }
            finally { _submissionLock.Release(); }
        }

        /// <summary>
        /// Belirli bir dosya için önbellek kaydını geçersiz kılar.
        /// </summary>
        public async Task InvalidateAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return;
            await MutateAsync(CacheWriteKind.Invalidate, filePath, cancellationToken);
        }

        /// <summary>Clears memory and persistent entries in submission order; failures are surfaced instead of acknowledged.</summary>
        public void Clear()
        {
            MutateAsync(CacheWriteKind.Clear, string.Empty, CancellationToken.None).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Waits for all previously accepted writes to commit; persistence failures are not acknowledged as success.
        /// </summary>
        public async Task FlushAsync(CancellationToken cancellationToken = default)
        {
            var request = new CacheWriteRequest(CacheWriteKind.Flush);
            await _submissionLock.WaitAsync(cancellationToken);
            try { await _writeChannel.Writer.WriteAsync(request, cancellationToken); }
            finally { _submissionLock.Release(); }
            await request.Completion!.Task.WaitAsync(cancellationToken);
        }

        /// <summary>
        /// Hedef klasör için son başarılı tarama tarihini döner.
        /// </summary>
        public async Task<DateTime?> GetLastScanTimeAsync(string targetPath, ScanType scanType, CancellationToken cancellationToken = default)
        {
            try
            {
                await using var conn = new SqliteConnection(_connectionString);
                await conn.OpenAsync(cancellationToken);
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    SELECT LastScanCompletedUtc FROM ScanHistoryV2
                    WHERE TargetDirectory = $dir AND ScanType = $type 
                    LIMIT 1;
                ";
                cmd.Parameters.AddWithValue("$dir", targetPath.TrimEnd('\\'));
                cmd.Parameters.AddWithValue("$type", (int)scanType);

                var result = await cmd.ExecuteScalarAsync(cancellationToken);
                if (result != null && DateTime.TryParse(result.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dt))
                {
                    return dt;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex) { _logger?.LogWarning(ex, "Scan history lookup failed: {Target}", targetPath); }
            return null;
        }

        /// <summary>
        /// Tamamlanan taramanın özet istatistiklerini ve zaman damgasını kaydeder.
        /// </summary>
        public async Task RecordScanCompletionAsync(
            string targetPath,
            ScanType scanType,
            int totalFiles,
            int skippedCachedFiles,
            int freshScannedFiles,
            int threatsFound,
            long durationMs,
            CancellationToken cancellationToken = default)
        {
            try
            {
                await using var conn = new SqliteConnection(_connectionString);
                await conn.OpenAsync(cancellationToken);
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO ScanHistoryV2
                    (TargetDirectory, ScanType, LastScanCompletedUtc, TotalFiles, SkippedCachedFiles, FreshScannedFiles, ThreatsFound, DurationMs)
                    VALUES ($dir, $type, $time, $tot, $skip, $fresh, $thr, $dur);
                ";
                cmd.Parameters.AddWithValue("$dir", targetPath.TrimEnd('\\'));
                cmd.Parameters.AddWithValue("$type", (int)scanType);
                cmd.Parameters.AddWithValue("$time", DateTime.UtcNow.ToString("o"));
                cmd.Parameters.AddWithValue("$tot", totalFiles);
                cmd.Parameters.AddWithValue("$skip", skippedCachedFiles);
                cmd.Parameters.AddWithValue("$fresh", freshScannedFiles);
                cmd.Parameters.AddWithValue("$thr", threatsFound);
                cmd.Parameters.AddWithValue("$dur", durationMs);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Scan history was not committed: {Target}", targetPath);
                if (ex is OperationCanceledException && cancellationToken.IsCancellationRequested) throw;
                throw new IOException("Scan completion history was not committed.", ex);
            }
        }

        private async Task WriteBatchToSqliteAsync(List<CachedScanVerdict> items, CancellationToken ct)
        {
            await _dbWriteLock.WaitAsync(ct);
            try
            {
                await using var conn = new SqliteConnection(_connectionString);
                await conn.OpenAsync(ct);
                await using var trans = (SqliteTransaction)await conn.BeginTransactionAsync(ct);

                await using var cmd = conn.CreateCommand();
                cmd.Transaction = trans;
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO ScanCacheEntries 
                    (CacheKey, FastPathKey, Sha256, FilePath, FileSize, LastWriteTimeUtc, Verdict, PolicyAction, 
                     RiskScore, RiskLevel, ThreatTitle, Confidence, EvidencesJson, CachedAtUtc, ExpiresAtUtc)
                    VALUES ($key, $fastKey, $sha, $path, $size, $writeTime, $verdict, $policy, 
                            $risk, $level, $title, $conf, $evid, $cachedAt, $expiresAt);
                ";

                var pKey = cmd.Parameters.Add("$key", SqliteType.Text);
                var pFastKey = cmd.Parameters.Add("$fastKey", SqliteType.Text);
                var pSha = cmd.Parameters.Add("$sha", SqliteType.Text);
                var pPath = cmd.Parameters.Add("$path", SqliteType.Text);
                var pSize = cmd.Parameters.Add("$size", SqliteType.Integer);
                var pWrite = cmd.Parameters.Add("$writeTime", SqliteType.Text);
                var pVerdict = cmd.Parameters.Add("$verdict", SqliteType.Integer);
                var pPolicy = cmd.Parameters.Add("$policy", SqliteType.Integer);
                var pRisk = cmd.Parameters.Add("$risk", SqliteType.Integer);
                var pLevel = cmd.Parameters.Add("$level", SqliteType.Integer);
                var pTitle = cmd.Parameters.Add("$title", SqliteType.Text);
                var pConf = cmd.Parameters.Add("$conf", SqliteType.Real);
                var pEvid = cmd.Parameters.Add("$evid", SqliteType.Text);
                var pCached = cmd.Parameters.Add("$cachedAt", SqliteType.Text);
                var pExpires = cmd.Parameters.Add("$expiresAt", SqliteType.Text);

                foreach (var v in items)
                {
                    string filePathSafe = v.FilePath ?? string.Empty;
                    string primaryKey = !string.IsNullOrWhiteSpace(v.SHA256)
                        ? GenerateKey(v.SHA256, v.FileSize, v.LastWriteTimeUtc)
                        : GenerateFastPathKey(filePathSafe, v.FileSize, v.LastWriteTimeUtc);

                    string fastKey = !string.IsNullOrWhiteSpace(filePathSafe)
                        ? GenerateFastPathKey(filePathSafe, v.FileSize, v.LastWriteTimeUtc)
                        : string.Empty;

                    DateTime expires = v.CachedAtUtc + _ttl;

                    pKey.Value = primaryKey;
                    pFastKey.Value = fastKey;
                    pSha.Value = v.SHA256 ?? string.Empty;
                    pPath.Value = v.FilePath ?? string.Empty;
                    pSize.Value = v.FileSize;
                    pWrite.Value = v.LastWriteTimeUtc.ToString("o");
                    pVerdict.Value = (int)v.Verdict;
                    pPolicy.Value = (int)v.RecommendedPolicy;
                    pRisk.Value = v.RiskScore;
                    pLevel.Value = (int)v.RiskLevel;
                    pTitle.Value = (object?)v.ThreatTitle ?? DBNull.Value;
                    pConf.Value = v.Confidence;
                    // Versioned full envelope; old evidence-only arrays cannot establish current coverage.
                    pEvid.Value = JsonSerializer.Serialize(v);
                    pCached.Value = v.CachedAtUtc.ToString("o");
                    pExpires.Value = expires.ToString("o");

                    await cmd.ExecuteNonQueryAsync(ct);
                }

                await trans.CommitAsync(ct);
            }
            finally
            {
                _dbWriteLock.Release();
            }
        }

        private static void PurgeExpiredEntriesInternal(SqliteConnection conn)
        {
            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM ScanCacheEntries WHERE ExpiresAtUtc < $now;";
                cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("o"));
                cmd.ExecuteNonQuery();
            }
            catch { }
        }

        private void EnforceL1Capacity()
        {
            if (_l1Cache.Count > _maxL1Entries)
            {
                int toRemove = Math.Max(100, _maxL1Entries / 10);
                int removed = 0;
                foreach (var k in _l1Cache.Keys)
                {
                    _l1Cache.TryRemove(k, out _);
                    removed++;
                    if (removed >= toRemove) break;
                }
            }
        }

        private void TightenFileAcl(string filePath)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || !File.Exists(filePath)) return;
            try
            {
                var fi = new FileInfo(filePath);
                var fs = new FileSecurity();
                fs.SetAccessRuleProtection(true, false);
                using var identity = WindowsIdentity.GetCurrent();
                if (identity.User != null)
                    fs.AddAccessRule(new FileSystemAccessRule(identity.User,
                        FileSystemRights.FullControl, AccessControlType.Allow));
                fs.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl, AccessControlType.Allow));
                fs.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    FileSystemRights.FullControl, AccessControlType.Allow));
                fs.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    FileSystemRights.ReadAndExecute, AccessControlType.Allow));
                fi.SetAccessControl(fs);
            }
            catch (Exception ex) { _logger?.LogWarning(ex, "Scan cache file ACL could not be applied: {Path}", filePath); }
        }

        /// <summary>Stops submissions and drains accepted writes; a slow writer keeps its semaphore until exit.</summary>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _writeChannel.Writer.TryComplete();
            // Do not dispose a semaphore while the draining writer can still use it.
            if (_writerTask.Wait(TimeSpan.FromSeconds(2))) _dbWriteLock.Dispose();
            else _ = _writerTask.ContinueWith(_ => _dbWriteLock.Dispose(), TaskScheduler.Default);
        }
    }
}
