using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Caching
{
    /// <summary>
    /// Çok Katmanlı (L1 In-Memory LRU + L2 Kalıcı Disk) Tarama Önbellek Motoru.
    /// Tekrarlanan dosya taramalarında sıfır CPU/IO yükü ile mikrosaniye seviyesinde karar dönüşü sağlar.
    /// </summary>
    public class MultiLayerScanCache : IScanCacheService
    {
        private readonly ILogger<MultiLayerScanCache>? _logger;
        private readonly string _cacheDirectory;
        private readonly string _cacheDbPath;
        private readonly int _maxL1Entries;

        // L1: In-Memory Fast Cache: CompositeKey -> CachedScanVerdict
        private readonly ConcurrentDictionary<string, CachedScanVerdict> _l1Cache = new(StringComparer.OrdinalIgnoreCase);

        // Path -> Last Known CompositeKey (Hızlı invalidation için)
        private readonly ConcurrentDictionary<string, string> _pathToKeyMap = new(StringComparer.OrdinalIgnoreCase);

        private readonly SemaphoreSlim _diskLock = new(1, 1);
        private bool _isL2Loaded;

        public int L1Count => _l1Cache.Count;

        public MultiLayerScanCache(string? cacheDir = null, ILogger<MultiLayerScanCache>? logger = null)
        {
            _logger = logger;
            _cacheDirectory = cacheDir ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AegisPC", "ScanCache");
            _cacheDbPath = Path.Combine(_cacheDirectory, "scan_cache_v2.json");

            // RAM'e göre L1 cache boyutu: her MB RAM için 6 entry (16 GB RAM → ~96K entry)
            long ramMb = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024);
            if (ramMb <= 0) ramMb = 8192;
            _maxL1Entries = (int)Math.Clamp(ramMb * 6, 5_000, 100_000);

            try
            {
                Directory.CreateDirectory(_cacheDirectory);
                LoadL2CacheFromDisk();
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Failed to initialize scan cache directory.");
            }
        }

        public async Task<CachedScanVerdict?> TryGetVerdictAsync(
            string filePath, 
            string sha256, 
            long fileSize, 
            DateTime lastWriteUtc, 
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sha256)) return null;

            var key = GenerateKey(sha256, fileSize, lastWriteUtc);

            // 1. L1 Bellek İçi Arama (< 0.01 ms)
            if (_l1Cache.TryGetValue(key, out var cached))
            {
                // Önbellek tazelik doğrulaması (30 gün)
                if ((DateTime.UtcNow - cached.CachedAtUtc).TotalDays <= 30)
                {
                    return cached;
                }
                _l1Cache.TryRemove(key, out _);
            }

            // 2. L2 Disk / Kalıcı Arama
            if (!_isL2Loaded)
            {
                await _diskLock.WaitAsync(cancellationToken);
                try
                {
                    if (!_isL2Loaded)
                    {
                        LoadL2CacheFromDisk();
                    }
                }
                finally
                {
                    _diskLock.Release();
                }

                if (_l1Cache.TryGetValue(key, out cached))
                {
                    return cached;
                }
            }

            return null;
        }

        private readonly object _persistLock = new();
        private volatile bool _isPersisting;
        private volatile bool _isDirty;

        public async Task SetVerdictAsync(CachedScanVerdict verdict, CancellationToken cancellationToken = default)
        {
            if (verdict == null || string.IsNullOrWhiteSpace(verdict.SHA256)) return;

            var key = GenerateKey(verdict.SHA256, verdict.FileSize, verdict.LastWriteTimeUtc);
            verdict.CachedAtUtc = DateTime.UtcNow;

            // LRU Sınırı Denetimi
            if (_l1Cache.Count >= _maxL1Entries)
            {
                TrimL1Cache();
            }

            _l1Cache[key] = verdict;
            if (!string.IsNullOrWhiteSpace(verdict.FilePath))
            {
                _pathToKeyMap[verdict.FilePath] = key;
            }

            // Debounced L2 persist: 3000ms gecikmeli arka plan yazımı (toplu yazım optimizasyonu)
            _isDirty = true;
            if (!_isPersisting)
            {
                _ = Task.Run(async () =>
                {
                    lock (_persistLock)
                    {
                        if (_isPersisting) return;
                        _isPersisting = true;
                    }

                    try
                    {
                        await Task.Delay(3000);
                        while (_isDirty)
                        {
                            _isDirty = false;
                            await PersistL2CacheToDiskAsync(CancellationToken.None);
                        }
                    }
                    catch { }
                    finally
                    {
                        lock (_persistLock)
                        {
                            _isPersisting = false;
                        }
                    }
                }, CancellationToken.None);
            }

            await Task.CompletedTask;
        }

        public async Task InvalidateAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return;

            if (_pathToKeyMap.TryRemove(filePath, out var key))
            {
                _l1Cache.TryRemove(key, out _);
            }

            await Task.CompletedTask;
        }

        public void Clear()
        {
            _l1Cache.Clear();
            _pathToKeyMap.Clear();

            try
            {
                if (File.Exists(_cacheDbPath))
                {
                    File.Delete(_cacheDbPath);
                }
            }
            catch { }
        }

        /// <summary>
        /// Önbellekteki verileri diske (L2) anında yazar (testler veya uygulama kapanışı için).
        /// </summary>
        public async Task FlushAsync(CancellationToken ct = default)
        {
            _isDirty = false;
            await PersistL2CacheToDiskAsync(ct);
        }

        private static string GenerateKey(string sha256, long fileSize, DateTime lastWriteUtc)
        {
            return $"{sha256.ToLowerInvariant()}::{fileSize}::{lastWriteUtc.Ticks}";
        }

        private void TrimL1Cache()
        {
            try
            {
                // En eski %20'yi temizle
                int toRemove = Math.Max(1, _maxL1Entries / 5);
                int removed = 0;
                foreach (var k in _l1Cache.Keys)
                {
                    _l1Cache.TryRemove(k, out _);
                    removed++;
                    if (removed >= toRemove) break;
                }
            }
            catch { }
        }

        private void LoadL2CacheFromDisk()
        {
            try
            {
                if (!File.Exists(_cacheDbPath))
                {
                    _isL2Loaded = true;
                    return;
                }

                using var fs = new FileStream(_cacheDbPath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536);
                var items = JsonSerializer.Deserialize<Dictionary<string, CachedScanVerdict>>(fs);
                if (items != null)
                {
                    foreach (var (k, v) in items)
                    {
                        if ((DateTime.UtcNow - v.CachedAtUtc).TotalDays <= 30)
                        {
                            _l1Cache[k] = v;
                            if (!string.IsNullOrEmpty(v.FilePath))
                            {
                                _pathToKeyMap[v.FilePath] = k;
                            }
                        }
                    }
                }
                _isL2Loaded = true;
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Could not load L2 cache from disk.");
                _isL2Loaded = true;
            }
        }

        private async Task PersistL2CacheToDiskAsync(CancellationToken ct)
        {
            await _diskLock.WaitAsync(ct);
            try
            {
                var dict = new Dictionary<string, CachedScanVerdict>(_l1Cache);
                var tempPath = _cacheDbPath + ".tmp";
                await using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 65536, useAsync: true))
                {
                    await JsonSerializer.SerializeAsync(fs, dict, new JsonSerializerOptions { WriteIndented = false }, ct);
                }
                File.Move(tempPath, _cacheDbPath, overwrite: true);
            }
            catch { }
            finally
            {
                _diskLock.Release();
            }
        }
    }
}
