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
        /// <summary>Absent/old rules require reanalysis.</summary>
        public string RuleSetVersion { get; set; } = string.Empty;
        /// <summary>Catalog identity; visibility preferences never affect it.</summary>
        public string IntelIdentity { get; set; } = string.Empty;
        /// <summary>Coverage is independent of the verdict enum.</summary>
        public bool InspectionComplete { get; set; }
        /// <summary>Explicit policy exemptions are re-evaluated, never frozen as clean cache decisions.</summary>
        public bool PolicyBypassed { get; set; }
        /// <summary>Explicit inspection omissions.</summary>
        public string[] CoverageLimitations { get; set; } = [];
        /// <summary>Typed classification, legacy safe.</summary>
        public SoftwareFindingClass SoftwareClass { get; set; }
        /// <summary>Authenticated source details.</summary>
        public AegisPC.Core.Models.SoftwareClassificationMetadata? SoftwareClassification { get; set; }
        /// <summary>Mixed records must never be hidden.</summary>
        public bool HasIndependentMalwareEvidence { get; set; }
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
