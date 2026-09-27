using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.Security.Diagnostics;
using Xunit;

namespace AegisPC.Tests
{
    public class IncidentTimelineExporterTests : IDisposable
    {
        private readonly string _testDir;
        private readonly List<SecurityIncident> _sampleIncidents;

        public IncidentTimelineExporterTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "AegisPC_TimelineExport_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);

            _sampleIncidents = new List<SecurityIncident>
            {
                new SecurityIncident
                {
                    IncidentId = "INC-20260910-001",
                    Title = "Fidye Yazılımı Davranışı Engellendi",
                    ThreatName = "Ransom.WannaCry",
                    RiskScore = 95,
                    RiskLevel = "CRITICAL",
                    Status = "Resolved",
                    ActionTaken = "Quarantined",
                    RootProcessName = "malware.exe",
                    RootPid = 4096,
                    RootExecutablePath = @"C:\Users\Test\AppData\Local\Temp\malware.exe",
                    Timeline = new List<string>
                    {
                        "[14:30:00] Süreç başlatıldı (PID: 4096)",
                        "[14:30:01] 25 adet dosya uzantısı .locked yapıldı",
                        "[14:30:02] Süreç durduruldu ve dosya karantinaya alındı"
                    }
                }
            };
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testDir))
                {
                    Directory.Delete(_testDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public void ExportToJson_ProducesValidAndDetailedJson()
        {
            var exporter = new IncidentTimelineExporter();
            string json = exporter.ExportToJson(_sampleIncidents);

            Assert.False(string.IsNullOrWhiteSpace(json));
            Assert.Contains("INC-20260910-001", json);
            Assert.Contains("Ransom.WannaCry", json);

            // Valid JSON deserialization
            using var doc = JsonDocument.Parse(json);
            Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
            Assert.Equal(1, doc.RootElement.GetArrayLength());
        }

        [Fact]
        public void ExportToCsv_ProducesStandardHeaderAndRows()
        {
            var exporter = new IncidentTimelineExporter();
            string csv = exporter.ExportToCsv(_sampleIncidents);

            Assert.False(string.IsNullOrWhiteSpace(csv));
            var lines = csv.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            Assert.True(lines.Length >= 2);

            // Header line
            Assert.Contains("IncidentId", lines[0]);
            Assert.Contains("TimelineEvents", lines[0]);

            // Data line
            Assert.Contains("INC-20260910-001", lines[1]);
            Assert.Contains("Ransom.WannaCry", lines[1]);
            Assert.Contains("4096", lines[1]);
        }

        [Fact]
        public async Task ExportToFileAsync_WritesJsonAndCsvFilesCorrectly()
        {
            var exporter = new IncidentTimelineExporter();

            string jsonPath = Path.Combine(_testDir, "incidents.json");
            string csvPath = Path.Combine(_testDir, "incidents.csv");

            await exporter.ExportToFileAsync(_sampleIncidents, jsonPath, "json");
            await exporter.ExportToFileAsync(_sampleIncidents, csvPath, "csv");

            Assert.True(File.Exists(jsonPath));
            Assert.True(File.Exists(csvPath));

            string readJson = await File.ReadAllTextAsync(jsonPath);
            Assert.Contains("INC-20260910-001", readJson);

            string readCsv = await File.ReadAllTextAsync(csvPath);
            Assert.Contains("IncidentId", readCsv);
            Assert.Contains("Ransom.WannaCry", readCsv);
        }
    }
}
