using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.PE
{
    /// <summary>
    /// Taşınabilir Yürütülebilir (PE) dosyaları güvenli, dosya kilidi bırakmayan bellek tamponlarıyla
    /// ayrıştıran, Rich Header, TLS Callbacks, Bölüm Anomalileri ve Authenticode zincirini doğrulayan derin analiz motoru.
    /// </summary>
    public interface IDeepPeAnalyzer
    {
        /// <summary>
        /// Disk üzerindeki dosyayı güvenle okur ve derin PE analizini gerçekleştirir.
        /// </summary>
        Task<PeDeepAnalysisResult> AnalyzeAsync(string filePath, CancellationToken cancellationToken = default);

        /// <summary>
        /// Bellekteki byte dizisi üzerinden PE başlık ve güvenlik analizini gerçekleştirir.
        /// </summary>
        PeDeepAnalysisResult Analyze(byte[] peBytes, string filePath = "");
    }
}
