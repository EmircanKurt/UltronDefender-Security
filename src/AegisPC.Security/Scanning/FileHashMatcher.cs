using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Dosya hash hesaplama, beyaz liste (Allowlist) sorgusu,
    /// WHQL/Microsoft dijital imza hızlı atlaması ve çok katmanlı önbellek arayüzü.
    /// </summary>
    public interface IFileHashMatcher
    {
        /// <summary>
        /// Değişmemiş dosyalar için önbellekten önceki tarama sonucunu sorgular.
        /// </summary>
        bool TryGetCached(string path, FileInfo fileInfo, bool isGameDir, out SecurityFinding? finding);

        /// <summary>
        /// Tarama sonucunu önbelleğe yazar (FIFO tahliyeli).
        /// </summary>
        void SetCache(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding);

        /// <summary>
        /// Dosyanın SHA-256 özetini hesaplar, beyaz liste ve Microsoft sistem imzası durumunu değerlendirir.
        /// </summary>
        Task<(string sha256, bool isAllowlisted, bool isMicrosoftBypassed)> EvaluateHashAndAllowlistAsync(string path, CancellationToken ct);
    }

    /// <summary>
    /// Tarama sırasında dosya hash'lerini, güvenli beyaz listeyi ve imza bypass mantığını yöneten sınıf.
    /// Cache limitleri sistemin RAM miktarına göre dinamik olarak hesaplanır.
    /// </summary>
    public class FileHashMatcher : IFileHashMatcher
    {
        private readonly IHashService _hashService;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IAllowlistService _allowlistService;

        // RAM'e göre dinamik cache limitleri (constructor'da hesaplanır)
        private readonly int _maxCacheEntries;
        private readonly int _maxSignatureCacheEntries;
        private readonly ConcurrentDictionary<string, (long FileSize, DateTime LastWriteTimeUtc, SecurityFinding? Finding, string? Sha256, bool IsAllowlisted, bool IsBypassed)> _scanCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentQueue<string> _cacheKeyQueue = new();
        private readonly ConcurrentDictionary<string, byte> _queuedCacheKeys = new(StringComparer.OrdinalIgnoreCase);

        // İmza kararı önbelleği: pahalı WinVerifyTrust/chain doğrulaması dosya sürümü başına bir kez yapılır
        private readonly ConcurrentDictionary<string, (long FileSize, DateTime LastWriteTimeUtc, bool Trusted)> _signatureCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentQueue<string> _signatureCacheQueue = new();

        public FileHashMatcher(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IAllowlistService allowlistService)
        {
            _hashService = hashService;
            _signatureVerifier = signatureVerifier;
            _allowlistService = allowlistService;

            // RAM'e göre cache boyutları: her MB RAM için ~50 scan cache, ~25 signature cache
            long ramMb = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024);
            if (ramMb <= 0) ramMb = 8192; // 8 GB fallback
            _maxCacheEntries = (int)Math.Clamp(ramMb * 50, 100_000, 500_000);
            _maxSignatureCacheEntries = (int)Math.Clamp(ramMb * 25, 50_000, 200_000);
        }

        public bool TryGetCached(string path, FileInfo fileInfo, bool isGameDir, out SecurityFinding? finding)
        {
            finding = null;
            if (_scanCache.TryGetValue(path, out var cached))
            {
                if (cached.FileSize == fileInfo.Length && cached.LastWriteTimeUtc == fileInfo.LastWriteTimeUtc)
                {
                    var ext = fileInfo.Extension.ToLowerInvariant();
                    // Eski sahte tespitleri (oyun, mod, zip) önbellekten dönmeyip temizce değerlendir
                    if (cached.Finding == null || (!isGameDir && ext != ".zip"))
                    {
                        // EĞER dosya beyaz listeye / çözüldüye eklenmişse veya cached finding çözüldüyse asla tehdit dönme
                        if (cached.Finding != null && (cached.Finding.Status == FindingStatus.Resolved || cached.Finding.IsAllowlisted))
                        {
                            _scanCache[path] = (cached.FileSize, cached.LastWriteTimeUtc, null, cached.Sha256, true, cached.IsBypassed);
                            finding = null;
                            return true;
                        }

                        if (_allowlistService != null && _allowlistService.IsPathAllowlistedAsync(path).GetAwaiter().GetResult())
                        {
                            _scanCache[path] = (cached.FileSize, cached.LastWriteTimeUtc, null, cached.Sha256, true, cached.IsBypassed);
                            finding = null;
                            return true;
                        }

                        if (!string.IsNullOrEmpty(cached.Sha256) && _allowlistService != null && _allowlistService.IsAllowlistedAsync(cached.Sha256).GetAwaiter().GetResult())
                        {
                            _scanCache[path] = (cached.FileSize, cached.LastWriteTimeUtc, null, cached.Sha256, true, cached.IsBypassed);
                            finding = null;
                            return true;
                        }

                        // Stale finding koruması: Meşru kurulum klasöründe yer alan veya güvenilir konuma taşınmış dosyaların eski hatalı bulgularını temizle
                        if (cached.Finding != null && AegisPC.Security.Safety.TrustedSoftwarePolicy.IsLegitimateInstallLocation(path))
                        {
                            _scanCache[path] = (cached.FileSize, cached.LastWriteTimeUtc, null, cached.Sha256, false, true);
                            finding = null;
                            return true;
                        }

                        finding = cached.Finding;
                        return true;
                    }
                }
            }
            return false;
        }

        public void SetCache(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding)
        {
            SetCacheInternal(path, fileSize, lastWriteTimeUtc, finding, null, false, finding == null);
        }

        public void SetCache(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding, string? sha256, bool isAllowlisted, bool isBypassed)
        {
            SetCacheInternal(path, fileSize, lastWriteTimeUtc, finding, sha256, isAllowlisted, isBypassed);
        }

        private void SetCacheInternal(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding, string? sha256, bool isAllowlisted, bool isBypassed)
        {
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
            _scanCache[path] = (fileSize, lastWriteTimeUtc, finding, sha256, isAllowlisted, isBypassed);
            if (_queuedCacheKeys.TryAdd(path, 0))
            {
                _cacheKeyQueue.Enqueue(path);
            }
        }

        /// <summary>
        /// Hash'siz geçiş için güvenilir konum: Windows dizini, Program Files ve meşru yazılım kurulum dizinleri.
        /// </summary>
        private static bool IsTrustedLocation(string path)
        {
            return AegisPC.Security.Safety.TrustedSoftwarePolicy.IsLegitimateInstallLocation(path);
        }

        /// <summary>
        /// Zincir doğrulaması geçmiş bir sertifikadaki yayıncı, güvenilir OS veya ticari yayıncı mı?
        /// </summary>
        private static bool IsTrustedPublisher(string? publisher)
        {
            if (string.IsNullOrEmpty(publisher)) return false;
            return AegisPC.Security.Safety.TrustedSoftwarePolicy.IsTrustedOsPublisher(publisher)
                || AegisPC.Security.Safety.TrustedSoftwarePolicy.IsTrustedCommercialPublisher(publisher);
        }

        public async Task<(string sha256, bool isAllowlisted, bool isMicrosoftBypassed)> EvaluateHashAndAllowlistAsync(string path, CancellationToken ct)
        {
            // 0. Kullanıcı tarafından çözüldü / güvenli işaretlenmiş yol kontrolü
            if (await _allowlistService.IsPathAllowlistedAsync(path, ct))
            {
                return (string.Empty, true, false);
            }

            // 1. Önce Scan-Cache kontrolü: Aynı dosya daha önce tarandıysa tekrar hash'leme
            FileInfo? fileInfo = null;
            try
            {
                fileInfo = new FileInfo(path);
                if (fileInfo.Exists && _scanCache.TryGetValue(path, out var cached))
                {
                    if (cached.FileSize == fileInfo.Length && cached.LastWriteTimeUtc == fileInfo.LastWriteTimeUtc)
                    {
                        if (cached.IsBypassed)
                        {
                            return (string.Empty, false, true);
                        }
                        if (cached.IsAllowlisted)
                        {
                            return (cached.Sha256 ?? string.Empty, true, false);
                        }
                        if (!string.IsNullOrEmpty(cached.Sha256))
                        {
                            if (await _allowlistService.IsAllowlistedAsync(cached.Sha256, ct))
                            {
                                SetCacheInternal(path, cached.FileSize, cached.LastWriteTimeUtc, null, cached.Sha256, true, false);
                                return (cached.Sha256, true, false);
                            }
                            return (cached.Sha256, false, false);
                        }
                    }
                }
            }
            catch { }

            // 2. Fast-Path: Güvenilir sistem konumlarındaki (Windows/Program Files) dijital imzalı dosyaları
            // diskten hash hesaplamadan ÖNCE kontrol et. Geçerli Microsoft veya bilinen ticari yayımcı imzası varsa hash'lemeyi atla.
            try
            {
                if (fileInfo != null && fileInfo.Exists && IsTrustedLocation(path))
                {
                    long sigSize = fileInfo.Length;
                    DateTime sigMtime = fileInfo.LastWriteTimeUtc;

                    if (_signatureCache.TryGetValue(path, out var sigEntry))
                    {
                        if (sigEntry.FileSize == sigSize && sigEntry.LastWriteTimeUtc == sigMtime)
                        {
                            if (sigEntry.Trusted)
                            {
                                return (string.Empty, false, true);
                            }
                        }
                        else
                        {
                            _signatureCache.TryRemove(path, out _);
                        }
                    }

                    var sig = await _signatureVerifier.VerifySignatureAsync(path, ct);
                    bool trusted = sig.IsSigned && sig.IsValid && IsTrustedPublisher(sig.Publisher);

                    if (_signatureCache.Count >= _maxSignatureCacheEntries && _signatureCacheQueue.TryDequeue(out var oldSigKey))
                    {
                        _signatureCache.TryRemove(oldSigKey, out _);
                    }
                    _signatureCache[path] = (sigSize, sigMtime, trusted);
                    _signatureCacheQueue.Enqueue(path);

                    if (trusted)
                    {
                        SetCacheInternal(path, sigSize, sigMtime, null, string.Empty, false, true);
                        return (string.Empty, false, true);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Signature evaluation failed for {path}: {ex.Message}");
            }

            // 3. İmzasız veya kullanıcı konumundaki dosyalar için SHA-256 hesapla
            var sha256 = await _hashService.ComputeSha256Async(path, ct);

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
                    long sz = fileInfo?.Length ?? 0;
                    DateTime mtime = fileInfo?.LastWriteTimeUtc ?? DateTime.MinValue;
                    SetCacheInternal(path, sz, mtime, null, sha256, false, false);
                    return (sha256, false, false);
                }
            }

            // 5. Kullanıcı tanımlı Güvenli Beyaz Liste (Allowlist)
            if (!string.IsNullOrEmpty(sha256) && (await _allowlistService.IsAllowlistedAsync(sha256, ct) || await _allowlistService.IsPathAllowlistedAsync(path, ct)))
            {
                long sz = fileInfo?.Length ?? 0;
                DateTime mtime = fileInfo?.LastWriteTimeUtc ?? DateTime.MinValue;
                SetCacheInternal(path, sz, mtime, null, sha256, true, false);
                return (sha256, true, false);
            }

            if (!string.IsNullOrEmpty(sha256))
            {
                long sz = fileInfo?.Length ?? 0;
                DateTime mtime = fileInfo?.LastWriteTimeUtc ?? DateTime.MinValue;
                SetCacheInternal(path, sz, mtime, null, sha256, false, false);
            }

            return (sha256 ?? string.Empty, false, false);
        }
    }
}
