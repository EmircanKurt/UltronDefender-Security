using System;
using System.Collections.Generic;
using AegisPC.Core.Enums;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı dosya analizi sonucunu ve telemetri ölçümlerini temsil eden model.
    /// Tespit süresi (TTD) ve müdahale süresi (TTA) ölçümlerini barındırır.
    /// </summary>
    public class RealTimeVerdictResult
    {
        /// <summary>
        /// Dosyanın nihai kararı (Clean, Suspicious, ConfirmedMalicious).
        /// </summary>
        public RealTimeVerdict Verdict { get; set; }

        /// <summary>
        /// Kararın güven derecesi (0.0 - 1.0 arası).
        /// </summary>
        public double Confidence { get; set; }

        /// <summary>
        /// Hesaplanan risk skoru (0 - 100 arası).
        /// </summary>
        public int RiskScore { get; set; }

        /// <summary>
        /// Dosyanın sınıflandırıldığı risk kategorisi seviyesi.
        /// </summary>
        public RiskLevel RiskLevel { get; set; }

        /// <summary>
        /// Tehdit tespit edildiyse tehdidin başlığı veya zararlı yazılım adı.
        /// </summary>
        public string ThreatTitle { get; set; } = string.Empty;

        /// <summary>
        /// Tehdit hakkında açıklayıcı teknik detay.
        /// </summary>
        public string ThreatDescription { get; set; } = string.Empty;

        /// <summary>
        /// Kararın verilmesinde rol oynayan kanıtların ve göstergelerin listesi.
        /// </summary>
        public List<string> Evidences { get; set; } = new();

        /// <summary>
        /// Bu karar için uygulanması önerilen politika eylemi (Allow, Warn, BlockAndQuarantine).
        /// </summary>
        public RealTimePolicyAction RecommendedPolicy { get; set; }

        /// <summary>
        /// İncelenen dosyanın SHA-256 kriptografik özeti.
        /// </summary>
        public string SHA256 { get; set; } = string.Empty;

        /// <summary>
        /// Dosya sistemi olayının oluştuğu UTC zamanı.
        /// </summary>
        public DateTime EventTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Taramaya başlanma UTC zamanı.
        /// </summary>
        public DateTime ScanStartTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Taramanın bittiği UTC zamanı.
        /// </summary>
        public DateTime ScanEndTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Kararın üretildiği UTC zamanı.
        /// </summary>
        public DateTime VerdictTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Müdahale eyleminin tamamlandığı UTC zamanı.
        /// </summary>
        public DateTime ActionTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Tespit Süresi (Time-to-Detect): Olay anından tarama ve karar bitimine kadar geçen milisaniye.
        /// </summary>
        public double TimeToDetectMs => (ScanEndTime - EventTime).TotalMilliseconds > 0 
            ? (ScanEndTime - EventTime).TotalMilliseconds 
            : Math.Max(0.1, (ScanEndTime - ScanStartTime).TotalMilliseconds);

        /// <summary>
        /// Müdahale Süresi (Time-to-Action): Olay anından eylemin (karantina/izin) tamamlanmasına kadar geçen milisaniye.
        /// </summary>
        public double TimeToActionMs => (ActionTime - EventTime).TotalMilliseconds > 0 
            ? (ActionTime - EventTime).TotalMilliseconds 
            : Math.Max(0.1, (ActionTime - ScanStartTime).TotalMilliseconds);
    }
}
