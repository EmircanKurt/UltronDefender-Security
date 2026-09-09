using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
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
    public class ScanCacheService : IScanCacheService, IDisposable
    {
        private readonly ILogger<ScanCacheService>? _logger;
        private readonly string _dbPath;
        private readonly string _connectionString;
        private readonly TimeSpan _ttl;
        private readonly int _maxL1Entries;

        // L1 In-Memory Cache: Key -> CachedScanVerdict
        private readonly ConcurrentDictionary<string, CachedScanVerdict> _l1Cache = new(StringComparer.OrdinalIgnoreCase);
        // FastPath Cache: FilePath -> FastPathKey
        private readonly ConcurrentDictionary<string, string> _pathToKeyMap = new(StringComparer.OrdinalIgnoreCase);

        // Background Batch Writer Channel
        private readonly Channel<CachedScanVerdict> _writeChannel;
        private readonly Task _writerTask;
        private readonly CancellationTokenSource _cts = new();
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
            _writeChannel = Channel.CreateBounded<CachedScanVerdict>(new BoundedChannelOptions(50_000)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
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
                ";
                cmd.ExecuteNonQuery();

                // Başlangıçta süresi dolmuş eski kayıtları temizle
                PurgeExpiredEntriesInternal(conn);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "ScanCache.db ilklendirilirken hata oluştu.");
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
            if (string.IsNullOrWhiteSpace(sha256) && string.IsNullOrWhiteSpace(filePath))
                return null;

            string key = !string.IsNullOrWhiteSpace(sha256)
                ? GenerateKey(sha256, fileSize, lastWriteUtc)
                : GenerateFastPathKey(filePath, fileSize, lastWriteUtc);

            // 1. L1 Bellek İçi Hızlı Arama (< 0.005 ms)
            if (_l1Cache.TryGetValue(key, out var cached))
            {
                // TTL Kontrolü: 7 gün aşılmışsa taze tarama zorunlu kıl
                if (DateTime.UtcNow > cached.CachedAtUtc + _ttl)
                {
                    _l1Cache.TryRemove(key, out _);
                    return null;
                }
                return cached;
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
                    var expiresUtc = DateTime.Parse(reader.GetString(12));
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
                        LastWriteTimeUtc = DateTime.Parse(reader.GetString(3)),
                        Verdict = (RealTimeVerdict)reader.GetInt32(4),
                        RecommendedPolicy = (RealTimePolicyAction)reader.GetInt32(5),
                        RiskScore = reader.GetInt32(6),
                        RiskLevel = (RiskLevel)reader.GetInt32(7),
                        ThreatTitle = reader.IsDBNull(8) ? string.Empty : reader.GetString(8),
                        Confidence = reader.GetDouble(9),
                        CachedAtUtc = DateTime.Parse(reader.GetString(11))
                    };

                    if (!reader.IsDBNull(10))
                    {
                        try
                        {
                            verdict.Evidences = JsonSerializer.Deserialize<List<string>>(reader.GetString(10)) ?? new();
                        }
                        catch { }
                    }

                    // L1 önbelleğe al
                    EnforceL1Capacity();
                    _l1Cache[key] = verdict;
                    if (!string.IsNullOrEmpty(verdict.FilePath))
                    {
                        _pathToKeyMap[verdict.FilePath] = key;
                    }

                    return verdict;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "ScanCache.db sorgulanırken hata oluştu: {Key}", key);
            }

            return null;
        }

        /// <summary>
        /// Hızlı Yol (FastPath): Dosya içeriğini diskten okumadan yalnızca dosya yolu, boyut ve tarih ile arar.
        /// </summary>
        public async Task<CachedScanVerdict?> TryGetFastVerdictAsync(
            string filePath,
            long fileSize,
            DateTime lastWriteUtc,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return null;

            string fastKey = GenerateFastPathKey(filePath, fileSize, lastWriteUtc);
            if (_l1Cache.TryGetValue(fastKey, out var cached))
            {
                if (DateTime.UtcNow > cached.CachedAtUtc + _ttl)
                {
                    _l1Cache.TryRemove(fastKey, out _);
                    return null;
                }
                return cached;
            }

            return await TryGetVerdictAsync(filePath, string.Empty, fileSize, lastWriteUtc, cancellationToken);
        }

        /// <summary>
        /// Tarama sonucunu önbelleğe yazar (L1 bellek + arka plan L2 SQLite kuyruğu).
        /// </summary>
        public async Task SetVerdictAsync(CachedScanVerdict verdict, CancellationToken cancellationToken = default)
        {
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

            // 1. L1 Bellek İçi Anında Güncelleme
            EnforceL1Capacity();
            _l1Cache[primaryKey] = verdict;
            if (!string.IsNullOrEmpty(fastKey))
            {
                _l1Cache[fastKey] = verdict;
                _pathToKeyMap[verdict.FilePath] = fastKey;
            }

            // 2. L2 Arka Plan Toplu Yazım Kuyruğuna Ekle (Non-Blocking)
            _writeChannel.Writer.TryWrite(verdict);
            await Task.CompletedTask;
        }

        /// <summary>
        /// Belirli bir dosya için önbellek kaydını geçersiz kılar.
        /// </summary>
        public async Task InvalidateAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return;

            if (_pathToKeyMap.TryRemove(filePath, out var fastKey))
            {
                _l1Cache.TryRemove(fastKey, out _);
            }

            try
            {
                await using var conn = new SqliteConnection(_connectionString);
                await conn.OpenAsync(cancellationToken);
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM ScanCacheEntries WHERE FilePath = $path;";
                cmd.Parameters.AddWithValue("$path", filePath);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Önbellek kaydı silinirken hata: {Path}", filePath);
            }
        }

        public void Clear()
        {
            _l1Cache.Clear();
            _pathToKeyMap.Clear();

            try
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM ScanCacheEntries;";
                cmd.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "ScanCacheEntries temizlenirken hata oluştu.");
            }
        }

        /// <summary>
        /// Arka planda bekleyen tüm önbellek yazım kuyruğunu diske anında döker (Flush).
        /// </summary>
        public async Task FlushAsync(CancellationToken cancellationToken = default)
        {
            while (_writeChannel.Reader.Count > 0)
            {
                await Task.Delay(20, cancellationToken);
            }
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
                    SELECT LastScanCompletedUtc FROM ScanHistory 
                    WHERE TargetDirectory = $dir AND ScanType = $type 
                    LIMIT 1;
                ";
                cmd.Parameters.AddWithValue("$dir", targetPath.TrimEnd('\\'));
                cmd.Parameters.AddWithValue("$type", (int)scanType);

                var result = await cmd.ExecuteScalarAsync(cancellationToken);
                if (result != null && DateTime.TryParse(result.ToString(), out var dt))
                {
                    return dt;
                }
            }
            catch { }
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
                    INSERT OR REPLACE INTO ScanHistory 
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
                _logger?.LogTrace(ex, "ScanHistory kaydedilemedi: {Dir}", targetPath);
            }
        }

        private async Task ProcessBatchWriteQueueAsync()
        {
            var batch = new List<CachedScanVerdict>(250);

            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    // İlk öğeyi bekle
                    if (await _writeChannel.Reader.WaitToReadAsync(_cts.Token))
                    {
                        while (_writeChannel.Reader.TryRead(out var item))
                        {
                            batch.Add(item);
                            if (batch.Count >= 250) break;
                        }

                        if (batch.Count > 0)
                        {
                            await WriteBatchToSqliteAsync(batch, _cts.Token);
                            batch.Clear();
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger?.LogTrace(ex, "ScanCache batch yazım sırasında hata.");
                    await Task.Delay(200);
                }
            }

            // Kapanışta kalanları yaz
            while (_writeChannel.Reader.TryRead(out var remaining))
            {
                batch.Add(remaining);
            }
            if (batch.Count > 0)
            {
                try
                {
                    await WriteBatchToSqliteAsync(batch, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to flush remaining scan cache batch to SQLite on shutdown.");
                }
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
                    pEvid.Value = v.Evidences?.Count > 0 ? JsonSerializer.Serialize(v.Evidences) : DBNull.Value;
                    pCached.Value = v.CachedAtUtc.ToString("o");
                    pExpires.Value = expires.ToString("o");

                    await cmd.ExecuteNonQueryAsync(ct);
                }

                await trans.CommitAsync(ct);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "SQLite batch commit sırasında hata.");
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

        private static void TightenFileAcl(string filePath)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || !File.Exists(filePath)) return;
            try
            {
                var fi = new FileInfo(filePath);
                var fs = new FileSecurity();
                fs.SetAccessRuleProtection(true, false);
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
            catch { }
        }

        public void Dispose()
        {
            try
            {
                _cts.Cancel();
                _writeChannel.Writer.Complete();
                _writerTask.Wait(TimeSpan.FromSeconds(2));
                _cts.Dispose();
                _dbWriteLock.Dispose();
            }
            catch { }
        }
    }
}
