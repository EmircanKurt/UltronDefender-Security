using System;
using System.Collections.Generic;

namespace AegisPC.Contracts.ThreatIntelligence
{
    public class ThreatIntelRecord
    {
        public string Sha256 { get; set; } = string.Empty;
        public string ThreatName { get; set; } = string.Empty;
        public string Category { get; set; } = "Malware";
        public int Severity { get; set; } = 100;
        public string Source { get; set; } = "LocalDatabase";
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Çok sinyalli dosya analizi için çevrimdışı öncelikli (offline-first) Tehdit İstihbarat Deposu.
    /// Bilinen zararlı hash'leri, bilinen temiz/güvenilir hash'leri ve doğrulanmış üreticileri yönetir.
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
        /// Yayımcı adının bilinen meşru işletim sistemi veya yazılım üreticisi olup olmadığını denetler.
        /// </summary>
        bool IsTrustedPublisher(string? publisher);

        /// <summary>
        /// Yeni bir zararlı hash kaydını istihbarat deposuna ekler.
        /// </summary>
        void RegisterMaliciousHash(string sha256, string threatName, string category = "Malware", int severity = 100);

        /// <summary>
        /// Güvenilir bilinen bir dosya hash'ini depoya ekler.
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
