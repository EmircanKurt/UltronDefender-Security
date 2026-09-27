using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    /// <summary>
    /// EDR ve güvenlik olay zaman çizelgelerini (timeline) JSON ve CSV formatlarında dışa aktaran servis arayüzü.
    /// </summary>
    public interface IIncidentTimelineExporter
    {
        string ExportToJson(IEnumerable<SecurityIncident> incidents);
        string ExportToCsv(IEnumerable<SecurityIncident> incidents);
        Task ExportToFileAsync(IEnumerable<SecurityIncident> incidents, string filePath, string format, CancellationToken ct = default);
    }
}
