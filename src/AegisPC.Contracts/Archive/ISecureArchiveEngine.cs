using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Archive
{
    /// <summary>
    /// Sıkıştırılmış arşivleri (ZIP, vb.) Zip Bomb / Decompression Bomb saldırılarına karşı
    /// sıkı kota ve genişleme sınırlarıyla güvenle açan ve analiz eden motor arayüzü.
    /// </summary>
    public interface ISecureArchiveEngine
    {
        Task<ArchiveScanVerdict> InspectArchiveAsync(string filePath, ArchiveSafetyLimits? limits = null, CancellationToken cancellationToken = default);
        Task<ArchiveScanVerdict> InspectArchiveStreamAsync(Stream stream, ArchiveSafetyLimits? limits = null, CancellationToken cancellationToken = default);
    }
}
