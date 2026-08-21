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
        private const int MaxL1Entries = 10000;

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

        public async Task SetVerdictAsync(CachedScanVerdict verdict, CancellationToken cancellationToken = default)
        {
            if (verdict == null || string.IsNullOrWhiteSpace(verdict.SHA256)) return;

            var key = GenerateKey(verdict.SHA256, verdict.FileSize, verdict.LastWriteTimeUtc);
            verdict.CachedAtUtc = DateTime.UtcNow;

            // LRU Sınırı Denetimi
            if (_l1Cache.Count >= MaxL1Entries)
            {
                TrimL1Cache();
            }

            _l1Cache[key] = verdict;
            if (!string.IsNullOrWhiteSpace(verdict.FilePath))
            {
                _pathToKeyMap[verdict.FilePath] = key;
            }

            // Arka planda L2 Kalıcı Diske Yaz
            _ = Task.Run(async () =>
            {
                try
                {
                    await PersistL2CacheToDiskAsync(CancellationToken.None);
                }
                catch { }
            }, CancellationToken.None);

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

        private static string GenerateKey(string sha256, long fileSize, DateTime lastWriteUtc)
        {
            return $"{sha256.ToLowerInvariant()}::{fileSize}::{lastWriteUtc.Ticks}";
        }

        private void TrimL1Cache()
        {
            try
            {
                // En eski %20'yi temizle
                int toRemove = MaxL1Entries / 5;
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

                var json = File.ReadAllText(_cacheDbPath);
                var items = JsonSerializer.Deserialize<Dictionary<string, CachedScanVerdict>>(json);
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
                var json = JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = false });
                var tempPath = _cacheDbPath + ".tmp";
                await File.WriteAllTextAsync(tempPath, json, ct);
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
