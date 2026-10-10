using System;
using System.Collections.Generic;

namespace AegisPC.Core.Models
{
    /// <summary>
    /// Yerel itibar kayıt modeli: dosyanın ilk görülme tarihi, türediği süreç ve geçmiş güvenlik durumu.
    /// </summary>
    public class LocalReputationRecord
    {
        public string SHA256 { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
        public string OriginProcess { get; set; } = string.Empty;
        public int ObservationCount { get; set; } = 1;
        public bool HasMaliciousIncident { get; set; } = false;
        public List<int> ScoreHistory { get; set; } = new();

        /// <summary>
        /// Dosya sistemde 6 aydan (180 gün) uzun süredir sorunsuz çalışıyorsa -10 puan güven indirimi kazanır.
        /// </summary>
        public bool IsEligibleForLongTermCleanDiscount =>
            !HasMaliciousIncident && (DateTime.UtcNow - FirstSeenUtc).TotalDays >= 180.0;
    }

    public class LocalReputationVerdict
    {
        public int ScoreModifier { get; set; } = 0;
        public string Reason { get; set; } = string.Empty;
        public DateTime? FirstSeenUtc { get; set; }
        public int AgeDays { get; set; }
        public bool IsLongTermClean { get; set; }
    }
}
