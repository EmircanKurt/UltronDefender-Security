using System;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services
{
    /// <summary>
    /// ETW Pre-Execution Tehdit Uyarısı Olay Modeli.
    /// </summary>
    public record PreExecThreatAlert
    {
        public int ProcessId { get; init; }
        public string ImagePath { get; init; } = string.Empty;
        public string CommandLine { get; init; } = string.Empty;
        public string ThreatTitle { get; init; } = string.Empty;
        public int RiskScore { get; init; }
        public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    }

    /// <summary>
    /// ETW Pre-Execution Süreç Değerlendirme ve İnfaz Kararı.
    /// </summary>
    public class PreExecDecision
    {
        public int ProcessId { get; set; }
        public string ImagePath { get; set; } = string.Empty;
        public bool WasSuspended { get; set; }
        public bool WasBlocked { get; set; }
        public bool TimedOut { get; set; }
        public bool Whitelisted { get; set; }
        public bool CacheHit { get; set; }
        public int RiskScore { get; set; }
        public string Reason { get; set; } = string.Empty;
    }

    /// <summary>
    /// Microsoft-Windows-Kernel-Process ETW tabanlı Pre-Execution (Başlatma Öncesi)
    /// Süreç Tarama ve Erken Müdahale Servisi Arayüzü.
    /// </summary>
    public interface IEtwPreExecProtectionService : IDisposable
    {
        /// <summary>
        /// Servisin aktif olarak çalışıp çalışmadığı.
        /// </summary>
        bool IsRunning { get; }

        /// <summary>
        /// Çekirdek ETW sağlayıcısına aktif olarak abone olunup olunmadığı.
        /// Abone olunamamışsa sistem FileSystemWatcher post-op moduna geri düşer.
        /// </summary>
        bool IsEtwSubscribed { get; }

        /// <summary>
        /// Süreç başlatma öncesinde bir tehdit engellendiğinde tetiklenen olay.
        /// </summary>
        event Action<PreExecThreatAlert>? OnThreatBlocked;

        /// <summary>
        /// Pre-Exec tarama servisini başlatır.
        /// </summary>
        void Start();

        /// <summary>
        /// Pre-Exec tarama servisini durdurur.
        /// </summary>
        void Stop();

        /// <summary>
        /// Belirtilen süreç kimliği ve dosya yolu için başlatma öncesi tarama ve infazı yürütür.
        /// Test edilebilirlik ve simülasyon amacıyla doğrudan çağrılabilir.
        /// </summary>
        Task<PreExecDecision> EvaluateProcessAsync(
            int processId,
            string imagePath,
            string commandLine = "",
            CancellationToken ct = default);
    }
}
