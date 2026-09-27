using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    /// <summary>
    /// Dosyaların makinedeki yaşam süresi, kökeni ve itibar geçmişini tutan yerel itibar servisi.
    /// </summary>
    public interface ILocalReputationService
    {
        Task RecordFileObservationAsync(
            string path,
            string sha256,
            string? originProcess = null,
            int? riskScore = null,
            CancellationToken ct = default);

        Task RecordIncidentAsync(string sha256, CancellationToken ct = default);

        Task<LocalReputationVerdict> EvaluateReputationAsync(string sha256, CancellationToken ct = default);
    }
}
