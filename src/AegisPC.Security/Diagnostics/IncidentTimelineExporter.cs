using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Diagnostics
{
    /// <summary>
    /// EDR ve olay inceleme zaman çizelgelerini (timeline) standart JSON ve CSV formatlarında dışa aktarır.
    /// </summary>
    public class IncidentTimelineExporter : IIncidentTimelineExporter
    {
        private readonly ILogger<IncidentTimelineExporter>? _logger;

        public IncidentTimelineExporter(ILogger<IncidentTimelineExporter>? logger = null)
        {
            _logger = logger;
        }

        public string ExportToJson(IEnumerable<SecurityIncident> incidents)
        {
            if (incidents == null) throw new ArgumentNullException(nameof(incidents));

            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            return JsonSerializer.Serialize(incidents, options);
        }

        public string ExportToCsv(IEnumerable<SecurityIncident> incidents)
        {
            if (incidents == null) throw new ArgumentNullException(nameof(incidents));

            var sb = new StringBuilder();
            sb.AppendLine("IncidentId,CreatedAt,Title,ThreatName,RiskScore,RiskLevel,Status,ActionTaken,RootProcess,RootPid,RootExecutablePath,TimelineEvents");

            foreach (var inc in incidents)
            {
                string timelineJoined = inc.Timeline != null ? string.Join(" | ", inc.Timeline) : string.Empty;

                sb.Append(EscapeCsv(inc.IncidentId)).Append(',');
                sb.Append(EscapeCsv(inc.CreatedAt.ToString("o"))).Append(',');
                sb.Append(EscapeCsv(inc.Title)).Append(',');
                sb.Append(EscapeCsv(inc.ThreatName)).Append(',');
                sb.Append(inc.RiskScore).Append(',');
                sb.Append(EscapeCsv(inc.RiskLevel)).Append(',');
                sb.Append(EscapeCsv(inc.Status)).Append(',');
                sb.Append(EscapeCsv(inc.ActionTaken)).Append(',');
                sb.Append(EscapeCsv(inc.RootProcessName)).Append(',');
                sb.Append(inc.RootPid).Append(',');
                sb.Append(EscapeCsv(inc.RootExecutablePath)).Append(',');
                sb.Append(EscapeCsv(timelineJoined));
                sb.AppendLine();
            }

            return sb.ToString();
        }

        public async Task ExportToFileAsync(
            IEnumerable<SecurityIncident> incidents,
            string filePath,
            string format,
            CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(filePath)) throw new ArgumentException("Dosya yolu boş olamaz.", nameof(filePath));

            string content;
            if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase) ||
                filePath.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
            {
                content = ExportToCsv(incidents);
            }
            else
            {
                content = ExportToJson(incidents);
            }

            string? dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            await File.WriteAllTextAsync(filePath, content, Encoding.UTF8, ct);
            _logger?.LogInformation("Olay zaman çizelgesi başarıyla dışa aktarıldı: {Path} ({Format})", filePath, format);
        }

        private static string EscapeCsv(string? field)
        {
            if (string.IsNullOrEmpty(field)) return "\"\"";
            string escaped = field.Replace("\"", "\"\"");
            return $"\"{escaped}\"";
        }
    }
}
