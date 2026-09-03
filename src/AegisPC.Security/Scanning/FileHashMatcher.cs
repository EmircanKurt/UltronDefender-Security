using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
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
    /// </summary>
    public class FileHashMatcher : IFileHashMatcher
    {
        private readonly IHashService _hashService;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IAllowlistService _allowlistService;

        private const int MaxCacheEntries = 10000;
        private readonly ConcurrentDictionary<string, (long FileSize, DateTime LastWriteTimeUtc, SecurityFinding? Finding)> _scanCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentQueue<string> _cacheKeyQueue = new();

        public FileHashMatcher(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IAllowlistService allowlistService)
        {
            _hashService = hashService;
            _signatureVerifier = signatureVerifier;
            _allowlistService = allowlistService;
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
                        finding = cached.Finding;
                        return true;
                    }
                }
            }
            return false;
        }

        public void SetCache(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding)
        {
            if (_scanCache.Count >= MaxCacheEntries)
            {
                // Sıfır tahsisli FIFO tahliye (Snapshot almadan mikrosaniyede temizlik)
                while (_scanCache.Count >= (MaxCacheEntries - 1000) && _cacheKeyQueue.TryDequeue(out var oldKey))
                {
                    _scanCache.TryRemove(oldKey, out _);
                }
            }
            _scanCache[path] = (fileSize, lastWriteTimeUtc, finding);
            _cacheKeyQueue.Enqueue(path);
        }

        public async Task<(string sha256, bool isAllowlisted, bool isMicrosoftBypassed)> EvaluateHashAndAllowlistAsync(string path, CancellationToken ct)
        {
            var sha256 = await _hashService.ComputeSha256Async(path, ct);
            if (!string.IsNullOrEmpty(sha256) && await _allowlistService.IsAllowlistedAsync(sha256, ct))
            {
                return (sha256, true, false);
            }

            // Fast-Path Microsoft / WHQL Dijital İmza Denetimi (System32 ve Program Files altındaki geçerli imzalı dosyalar)
            if (PathHelper.IsSystemPath(path) ||
                path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase))
            {
                var sig = await _signatureVerifier.VerifySignatureAsync(path, ct);
                if (sig.IsSigned && sig.IsValid && !string.IsNullOrEmpty(sig.Publisher) && (
                    sig.Publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                    sig.Publisher.Contains("Windows", StringComparison.OrdinalIgnoreCase) ||
                    sig.Publisher.Contains("Google", StringComparison.OrdinalIgnoreCase)))
                {
                    return (sha256, false, true);
                }
            }

            return (sha256, false, false);
        }
    }
}
