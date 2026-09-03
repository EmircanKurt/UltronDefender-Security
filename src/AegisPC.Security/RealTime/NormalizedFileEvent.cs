using System;
using AegisPC.Core.Enums;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı dosya sistemi izleyicisi tarafından yakalanıp normalleştirilmiş dosya olay modeli.
    /// Farklı dosya sistemi sağlayıcılarından gelen ham olayları ortak bir yapıda toplar.
    /// </summary>
    public class NormalizedFileEvent
    {
        /// <summary>
        /// Olayın benzersiz tanımlayıcısı.
        /// </summary>
        public Guid EventId { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Olay izleme ve telemetri ilişkilendirme kimliği (kısa hash).
        /// </summary>
        public string CorrelationId { get; set; } = Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();

        /// <summary>
        /// Olayın gerçekleştiği UTC zaman damgası.
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Olayın türü (Oluşturuldu, Değiştirildi, Yeniden Adlandırıldı, Silindi vb.).
        /// </summary>
        public RealTimeEventType EventType { get; set; }

        /// <summary>
        /// Olayın gerçekleştiği ham dosya yolu.
        /// </summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>
        /// Kanonik (canonical) hale getirilmiş ve normalleştirilmiş tam dosya yolu.
        /// </summary>
        public string NormalizedPath { get; set; } = string.Empty;

        /// <summary>
        /// Dosya yeniden adlandırıldıysa eski dosya yolu; aksi halde null.
        /// </summary>
        public string? OldFilePath { get; set; }

        /// <summary>
        /// Dosyanın bayt cinsinden boyutu.
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// Dosya uzantısı (küçük harf, ör. .exe).
        /// </summary>
        public string Extension { get; set; } = string.Empty;

        /// <summary>
        /// Olayı tetikleyen sürecin kimliği (varsa); aksi halde 0.
        /// </summary>
        public int ProcessId { get; set; }

        /// <summary>
        /// Olayın kaynağı (örneğin FileSystemWatcher, Minifilter).
        /// </summary>
        public string Source { get; set; } = "FileSystemWatcher";
    }
}
