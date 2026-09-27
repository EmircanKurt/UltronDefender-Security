using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using Serilog;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Dosya hash hesaplama, beyaz liste (Allowlist) sorgusu,
    /// WHQL/Microsoft dijital imza hızlı atlaması ve çok katmanlı önbellek arayüzü.
    /// </summary>
    public interface IFileHashMatcher
    {
        /// <summary>
        /// Önbellekte tutulan toplam kayıt sayısı (dosya tarama + dijital imza önbellekleri).
        /// </summary>
        int CachedEntriesCount { get; }

        /// <summary>
        /// Aktif bir taramanın yürütülüp yürütülmediğini belirten bayrak.
        /// </summary>
        bool IsScanActive { get; set; }

        /// <summary>
        /// Dış koordinatör veya tarayıcıdan gelen aktif tarama kontrol delegesi.
        /// </summary>
        Func<bool>? ActiveScanChecker { get; set; }

        /// <summary>
        /// Önbellek isabetiyle taranan dosya sayısı.
        /// </summary>
        int ScannedFromCache { get; }

        /// <summary>
        /// Dijital imza / beyaz liste doğrulamasıyla güvenli atlanan dosya sayısı.
        /// </summary>
        int SkippedSignedClean { get; }

        /// <summary>
        /// Diskten hash hesaplanarak ve motorla yeni taranan dosya sayısı.
        /// </summary>
        int NewlyScanned { get; }

        /// <summary>
        /// Kırılım sayaçlarını sıfırlar.
        /// </summary>
        void ResetCounters();

        /// <summary>
        /// Tarama ve imza önbelleklerini eşzamanlı ve kilitli olmayan (lock-free) yöntemle temizler.
        /// Aktif tarama varsa işlem reddedilir ve loglanır.
        /// </summary>
        void ClearCache();

        /// <summary>
        /// Değişmemiş dosyalar için önbellekten önceki tarama sonucunu sorgular.
        /// </summary>
        bool TryGetCached(string path, FileInfo fileInfo, bool isGameDir, out SecurityFinding? finding);
        Task<(bool Hit, SecurityFinding? Finding, string? VerifiedHash)> TryGetCachedAsync(
            string path, FileInfo info, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            bool hit = TryGetCached(path, info, false, out var finding);
            return Task.FromResult((hit, finding, (string?)null));
        }

        /// <summary>
        /// Tarama sonucunu önbelleğe yazar (FIFO tahliyeli).
        /// </summary>
        void SetCache(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding);

        /// <summary>
        /// Genişletilmiş parametrelerle tarama sonucunu önbelleğe yazar.
        /// </summary>
        void SetCache(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding, string? sha256, bool isAllowlisted, bool isBypassed);

        /// <summary>
        /// Caches a completed analysis only for its captured policy revision. Implementations supporting revisions
        /// reject results that became stale during analysis; the default retains compatibility with existing matchers.
        /// </summary>
        void SetCache(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding,
            string? sha256, bool isAllowlisted, bool isBypassed, long policyRevision)
            => SetCache(path, fileSize, lastWriteTimeUtc, finding, sha256, isAllowlisted, isBypassed);

        /// <summary>
        /// Dosyanın SHA-256 özetini hesaplar, beyaz liste ve Microsoft sistem imzası durumunu değerlendirir.
        /// </summary>
        Task<(string sha256, bool isAllowlisted, bool isMicrosoftBypassed)> EvaluateHashAndAllowlistAsync(string path, CancellationToken ct);
        Task<(string sha256, bool isAllowlisted, bool isMicrosoftBypassed)> EvaluateHashAndAllowlistAsync(
            string path, CancellationToken ct, string? verifiedHash) => EvaluateHashAndAllowlistAsync(path, ct);

        /// <summary>
        /// Belirli bir dosya yolu için tarama ve imza önbelleğini geçersiz kılar.
        /// </summary>
        void InvalidateCache(string path);
    }

    /// <summary>
    /// Tarama sırasında dosya hash'lerini, güvenli beyaz listeyi ve imza bypass mantığını yöneten sınıf.
    /// Cache limitleri sistemin RAM miktarına göre dinamik olarak hesaplanır.
    /// </summary>
    public class FileHashMatcher : IFileHashMatcher
    {
        private readonly IHashService _hashService;
        private readonly IAllowlistService _allowlistService;
        private readonly IExclusionService? _exclusionService;

        // RAM'e göre dinamik cache limitleri (constructor'da hesaplanır)
        private readonly int _maxCacheEntries;
        private readonly ConcurrentDictionary<string, (long FileSize, DateTime LastWriteTimeUtc, SecurityFinding? Finding, string? Sha256, bool IsAllowlisted, bool IsBypassed, long PolicyRevision)> _scanCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentQueue<string> _cacheKeyQueue = new();
        private readonly ConcurrentDictionary<string, byte> _queuedCacheKeys = new(StringComparer.OrdinalIgnoreCase);

        // Kırılım sayaçları (Lock-free thread safe)
        private int _scannedFromCache;
        private int _skippedSignedClean;
        private int _newlyScanned;

        public int ScannedFromCache => Volatile.Read(ref _scannedFromCache);
        public int SkippedSignedClean => Volatile.Read(ref _skippedSignedClean);
        public int NewlyScanned => Volatile.Read(ref _newlyScanned);

        public int CachedEntriesCount => _scanCache.Count;
        public bool IsScanActive { get; set; }
        public Func<bool>? ActiveScanChecker { get; set; }

        public void ResetCounters()
        {
            Interlocked.Exchange(ref _scannedFromCache, 0);
            Interlocked.Exchange(ref _skippedSignedClean, 0);
            Interlocked.Exchange(ref _newlyScanned, 0);
        }

        public void ClearCache()
        {
            if (IsScanActive || (ActiveScanChecker != null && ActiveScanChecker()))
            {
                Log.Warning("Aktif tarama devam ederken önbellek temizleme işlemi reddedildi.");
                return;
            }

            int count = _scanCache.Count;
            _scanCache.Clear();
            _cacheKeyQueue.Clear();
            _queuedCacheKeys.Clear();
            Log.Information("Tarama önbelleği temizlendi. {Count} önbellek kaydı temizlendi.", count);
        }

        public void InvalidateCache(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            _scanCache.TryRemove(path, out _);
            _queuedCacheKeys.TryRemove(path, out _);
            Log.Information("Tarama ve imza önbelleği geçersiz kılındı (InvalidateCache): {Path}", path);
        }

        public FileHashMatcher(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IAllowlistService allowlistService,
            IExclusionService? exclusionService = null)
        {
            _hashService = hashService;
            _allowlistService = allowlistService;
            _exclusionService = exclusionService;

            // Bound cache memory on low-RAM computers. An entry contains a path, hash, result
            // metadata and a FIFO key; hundreds of thousands of entries can cost hundreds of MB.
            long ramMb = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024);
            if (ramMb <= 0) ramMb = 8192; // 8 GB fallback
            _maxCacheEntries = (int)Math.Clamp(ramMb * 5, 10_000, 100_000);
        }

        public bool TryGetCached(string path, FileInfo fileInfo, bool isGameDir, out SecurityFinding? finding)
        {
            var result = TryGetCachedAsync(path, fileInfo, CancellationToken.None).GetAwaiter().GetResult();
            finding = result.Finding;
            return result.Hit;
        }

        /// <summary>
        /// Returns a cached verdict only after validating file metadata, current content, mutable threat hashes and policy revision.
        /// A policy change during the asynchronous hash check invalidates the result; cancellation propagates to the caller.
        /// </summary>
        public async Task<(bool Hit, SecurityFinding? Finding, string? VerifiedHash)> TryGetCachedAsync(
            string path, FileInfo fileInfo, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                fileInfo.Refresh();
                if (!_scanCache.TryGetValue(path, out var cached) || !fileInfo.Exists ||
                    cached.FileSize != fileInfo.Length || cached.LastWriteTimeUtc != fileInfo.LastWriteTimeUtc ||
                    string.IsNullOrEmpty(cached.Sha256) || cached.PolicyRevision != DetectionPolicyRevision.Current)
                    return (false, null, null);
                await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
                var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
                if (!string.Equals(hash, cached.Sha256, StringComparison.OrdinalIgnoreCase)) return (false, null, hash);
                // Re-query mutable threat databases; previous clean results cannot override new intelligence.
                if (MalwareSignatureDatabase.CheckHash(hash).IsMatched || ThreatSignatureDatabase.CheckHash(hash).IsMatched)
                    return (false, null, hash);
                // Explicit trust decisions are re-evaluated by the normal path, not frozen in the cache.
                if (cached.IsAllowlisted || cached.IsBypassed || cached.Finding?.Status == FindingStatus.Resolved ||
                    cached.Finding?.IsAllowlisted == true) return (false, null, hash);
                // A reload may occur while the content hash is being verified asynchronously.
                if (cached.PolicyRevision != DetectionPolicyRevision.Current) return (false, null, hash);
                Interlocked.Increment(ref _scannedFromCache);
                return (true, cached.Finding, hash);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Log.Debug(ex, "Cached content could not be verified for {Path}", path);
                return (false, null, null);
            }
        }

        /// <summary>
        /// Fingerprints and caches an already-completed verdict under the current policy for legacy callers.
        /// Long-running analyses should instead pass the revision captured before analysis to the revision-aware overload.
        /// </summary>
        public void SetCache(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding)
        {
            SetCacheInternal(path, fileSize, lastWriteTimeUtc, finding, null, false, false, DetectionPolicyRevision.Current);
        }

        /// <summary>
        /// Stores a completed verdict with an optional previously-computed hash under the current policy.
        /// Legacy callers remain compatible; the revision-aware overload is required to reject in-flight stale analyses.
        /// </summary>
        public void SetCache(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding, string? sha256, bool isAllowlisted, bool isBypassed)
        {
            SetCacheInternal(path, fileSize, lastWriteTimeUtc, finding, sha256, isAllowlisted, isBypassed, DetectionPolicyRevision.Current);
        }

        /// <summary>
        /// Publishes a completed scan with the revision captured before analysis. A changed policy prevents publication;
        /// a change racing the write leaves an old-revision entry that readers reject.
        /// </summary>
        public void SetCache(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding,
            string? sha256, bool isAllowlisted, bool isBypassed, long policyRevision)
        {
            SetCacheInternal(path, fileSize, lastWriteTimeUtc, finding, sha256, isAllowlisted, isBypassed, policyRevision);
        }

        private void SetCacheInternal(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding,
            string? sha256, bool isAllowlisted, bool isBypassed, long policyRevision)
        {
            if (policyRevision != DetectionPolicyRevision.Current) return;
            if (string.IsNullOrEmpty(sha256))
            {
                try
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                    sha256 = Convert.ToHexString(SHA256.HashData(stream));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    Log.Debug(ex, "Unable to fingerprint completed scan for {Path}", path);
                    return;
                }
            }
            if (policyRevision != DetectionPolicyRevision.Current) return;
            if (_scanCache.Count >= _maxCacheEntries)
            {
                // Sıfır tahsisli FIFO tahliye (Snapshot almadan mikrosaniyede temizlik)
                int evictCount = _maxCacheEntries / 10;
                while (_scanCache.Count >= (_maxCacheEntries - evictCount) && _cacheKeyQueue.TryDequeue(out var oldKey))
                {
                    _scanCache.TryRemove(oldKey, out _);
                    _queuedCacheKeys.TryRemove(oldKey, out _);
                }
            }
            _scanCache[path] = (fileSize, lastWriteTimeUtc, finding, sha256, isAllowlisted, isBypassed, policyRevision);
            if (_queuedCacheKeys.TryAdd(path, 0))
            {
                _cacheKeyQueue.Enqueue(path);
            }
        }

        public async Task<(string sha256, bool isAllowlisted, bool isMicrosoftBypassed)> EvaluateHashAndAllowlistAsync(string path, CancellationToken ct)
            => await EvaluateHashAndAllowlistAsync(path, ct, null);

        public async Task<(string sha256, bool isAllowlisted, bool isMicrosoftBypassed)> EvaluateHashAndAllowlistAsync(
            string path, CancellationToken ct, string? verifiedHash)
        {
            ct.ThrowIfCancellationRequested();

            // Always establish content identity before considering user trust.
            // Hash evaluation is NOT a completed scan and must not publish a clean cache entry.
            var sha256 = verifiedHash ?? await _hashService.ComputeSha256Async(path, ct);
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(sha256))
                throw new IOException("The file could not be hashed; no clean verdict is available.");

            if (sha256 == "VIRUS_INFECTED_OS_BLOCKED")
            {
                Interlocked.Increment(ref _newlyScanned);
                return (sha256, false, false);
            }

            // 4. Tehdit Veritabanı Kontrolü (MalwareSignatureDatabase + ThreatSignatureDatabase)
            if (!string.IsNullOrEmpty(sha256))
            {
                var malwareCheck = MalwareSignatureDatabase.CheckHash(sha256);
                if (!malwareCheck.IsMatched)
                {
                    var threatCheck = ThreatSignatureDatabase.CheckHash(sha256);
                    if (threatCheck.IsMatched)
                    {
                        malwareCheck = new MalwareSignatureMatch
                        {
                            IsMatched = true,
                            ThreatName = threatCheck.Name,
                            ThreatCategory = threatCheck.Category,
                            SeverityScore = threatCheck.Severity
                        };
                    }
                }

                if (malwareCheck.IsMatched)
                {

                    Interlocked.Increment(ref _newlyScanned);
                    return (sha256, false, false);
                }
            }

            // 5. Kullanıcı tanımlı Güvenli Beyaz Liste (Allowlist)
            if (!string.IsNullOrEmpty(sha256) && ((_exclusionService?.IsExcluded(path, sha256) ?? false) || await _allowlistService.IsAllowlistedAsync(sha256, ct) || await _allowlistService.IsPathAllowlistedAsync(path, ct)))
            {

                Interlocked.Increment(ref _skippedSignedClean);
                return (sha256, true, false);
            }

            Interlocked.Increment(ref _newlyScanned);
            return (sha256 ?? string.Empty, false, false);
        }
    }
}
