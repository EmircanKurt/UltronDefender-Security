using System;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı koruma hattında gerçekleşen canlı eylem ve telemetri olay modeli.
    /// UI canlı akış paneli ve güvenlik kayıtlarına olay bildirimi için kullanılır.
    /// </summary>
    public class RealTimeActivityEvent
    {
        /// <summary>
        /// İlgili dosya inceleme oturumunun ilişkilendirme kimliği.
        /// </summary>
        public string CorrelationId { get; set; } = Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();

        /// <summary>
        /// Olayın gerçekleştiği yerel zaman damgası.
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.Now;

        /// <summary>
        /// İncelenen dosyanın adı.
        /// </summary>
        public string FileName { get; set; } = string.Empty;

        /// <summary>
        /// İncelenen dosyanın tam yolu.
        /// </summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>
        /// Analiz aşaması (EVENT_CAPTURED, STABILITY_CHECK, SCAN_STARTED, ANALYSIS_COMPLETED, VERDICT, ACTION_APPLIED).
        /// </summary>
        public string Stage { get; set; } = string.Empty;

        /// <summary>
        /// Aşamayla ilgili açıklayıcı durum iletisi.
        /// </summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>
        /// Dosyanın hesaplanan risk skoru (0-100).
        /// </summary>
        public int RiskScore { get; set; }

        /// <summary>
        /// Güvenlik değerlendirme kararı (Clean, Suspicious, ConfirmedMalicious).
        /// </summary>
        public string Verdict { get; set; } = "Clean";

        /// <summary>
        /// Uygulanan güvenlik politikası eylemi (Allow, Warn, BlockAndQuarantine).
        /// </summary>
        public string Action { get; set; } = "Allow";

        /// <summary>
        /// Dosya gelişinden tespiti tamamlamaya kadar geçen süre (milisaniye).
        /// </summary>
        public double TimeToDetectMs { get; set; }

        /// <summary>
        /// Dosya gelişinden müdahalenin tamamlanmasına kadar geçen süre (milisaniye).
        /// </summary>
        public double TimeToActionMs { get; set; }

        /// <summary>
        /// Olayın önem derecesi (Info, Warning, Danger, Success).
        /// </summary>
        public string Severity { get; set; } = "Info";

        /// <summary>
        /// UI gösterimi için biçimlendirilmiş zaman metni.
        /// </summary>
        public string TimestampFormatted => Timestamp.ToString("HH:mm:ss");

        /// <summary>
        /// UI gösterimi için detaylı aşama metni.
        /// </summary>
        public string StageDetails => string.IsNullOrWhiteSpace(Message) ? $"{Stage} ({FilePath})" : $"{Stage}: {Message}";

        /// <summary>
        /// UI gösterimi için risk rozet metni.
        /// </summary>
        public string ScoreBadge => RiskScore > 0 ? $"{RiskScore}/100" : "Güvenli";

        /// <summary>
        /// UI gösterimi için uygulanan eylem metni.
        /// </summary>
        public string ActionTaken => Action;
    }
}
