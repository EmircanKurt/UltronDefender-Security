using System;

namespace AegisPC.Core.Models
{
    /// <summary>
    /// Otomatik karantinaya alınan dosyalar için 30 günlük geri alma günlüğü ("cofa") ve karar zinciri kaydı.
    /// </summary>
    public class QuarantineUndoEntry
    {
        public int QuarantineId { get; set; }
        public string OriginalPath { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string ThreatName { get; set; } = string.Empty;
        public int RiskScore { get; set; }
        public string DecisionChain { get; set; } = string.Empty;
        public DateTime QuarantinedAt { get; set; } = DateTime.UtcNow;
        public bool IsRestored { get; set; }
        public DateTime? RestoredAt { get; set; }

        /// <summary>
        /// 30 günlük geri alma penceresi (cofa süresi) içinde mi?
        /// </summary>
        public bool IsWithinGracePeriod => (DateTime.UtcNow - QuarantinedAt).TotalDays <= 30.0;
    }
}
