using System;
using System.Collections.Generic;

namespace AegisPC.Contracts.ThreatIntelligence
{
    /// <summary>Provenance of an exact hash, not an estimated malware probability.</summary>
    public enum ThreatIntelVerification { Unverified, BuiltInTestMarker, SignedPackage }

    public class ThreatIntelRecord
    {
        public string Sha256 { get; set; } = string.Empty;
        public string ThreatName { get; set; } = string.Empty;
        public string Category { get; set; } = "Malware";
        public int Severity { get; set; } = 100;
        public string Source { get; set; } = "LocalDatabase";
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public string SourceReference { get; set; } = string.Empty;
        public string PackageVersion { get; set; } = string.Empty;
        public ThreatIntelVerification Verification { get; set; }
        /// <summary>Expiry from an authenticated package; legacy values cannot support optional hiding.</summary>
        public DateTime ValidUntilUtc { get; set; }
        public bool IsAuthoritative => Verification is ThreatIntelVerification.BuiltInTestMarker or ThreatIntelVerification.SignedPackage;
    }

    /// <summary>
    /// Local-only exact intelligence and bounded review metadata.
    /// Source strings and caller labels are not publisher authentication or clean-content proof.
    /// </summary>
    public interface IThreatIntelligenceStore
    {
        /// <summary>
        /// Hash'in bilinen zararlı veritabanında bulunup bulunmadığını O(1) hızında sorgular.
        /// </summary>
        bool IsMaliciousHash(string sha256, out ThreatIntelRecord? record);

        /// <summary>
        /// Hash'in doğrulanmış temiz/güvenilir dosya veritabanında bulunup bulunmadığını sorgular.
        /// </summary>
        bool IsTrustedHash(string sha256);

        /// <summary>
        /// Compatibility display-name query. A name cannot certify an Authenticode chain; current implementation returns false.
        /// </summary>
        bool IsTrustedPublisher(string? publisher);

        /// <summary>
        /// Registers review-only metadata. A caller-supplied label cannot authorize a malware verdict.
        /// </summary>
        void RegisterMaliciousHash(string sha256, string threatName, string category = "Malware", int severity = 100);

        /// <summary>
        /// Retains a caller preference only; it cannot become verified clean-content evidence.
        /// </summary>
        void RegisterTrustedHash(string sha256);

        /// <summary>
        /// Depodaki toplam aktif zararlı imza sayısı.
        /// </summary>
        int MaliciousSignaturesCount { get; }

        /// <summary>
        /// Depodaki toplam güvenilir hash sayısı.
        /// </summary>
        int TrustedHashesCount { get; }
    }
}
