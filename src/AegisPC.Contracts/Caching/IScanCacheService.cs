using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;

namespace AegisPC.Contracts.Caching
{
    /// <summary>
    /// Önbelleğe alınmış tarama karar sonucu modeli.
    /// </summary>
    public class CachedScanVerdict
    {
        public string SHA256 { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public DateTime LastWriteTimeUtc { get; set; }
        public RealTimeVerdict Verdict { get; set; }
        public RealTimePolicyAction RecommendedPolicy { get; set; }
        public int RiskScore { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public double Confidence { get; set; }
        public string ThreatTitle { get; set; } = string.Empty;
        public List<string> Evidences { get; set; } = new();
        public DateTime CachedAtUtc { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Çok katmanlı (L1 Bellek İçi LRU + L2 Kalıcı Disk/SQLite) Tarama Önbellek Servisi.
    /// </summary>
    public interface IScanCacheService
    {
        /// <summary>
        /// Dosya için geçerli bir önbellek kaydı arar. Dosya boyutu veya son yazma tarihi değiştiyse önbellek geçersiz sayılır.
        /// </summary>
        Task<CachedScanVerdict?> TryGetVerdictAsync(string filePath, string sha256, long fileSize, DateTime lastWriteUtc, CancellationToken cancellationToken = default);

        /// <summary>
        /// Tarama kararını hem L1 bellek hem L2 kalıcı önbelleğe kaydeder.
        /// </summary>
        Task SetVerdictAsync(CachedScanVerdict verdict, CancellationToken cancellationToken = default);

        /// <summary>
        /// Belirli bir dosya veya hash için önbellek kayıtlarını geçersiz kılar (invalidation).
        /// </summary>
        Task InvalidateAsync(string filePath, CancellationToken cancellationToken = default);

        /// <summary>
        /// Tüm önbelleği temizler.
        /// </summary>
        void Clear();
    }
}
