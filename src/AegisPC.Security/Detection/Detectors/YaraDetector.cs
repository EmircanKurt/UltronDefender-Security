using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Detection.YaraEngine;

namespace AegisPC.Security.Detection.Detectors
{
    /// <summary>
    /// 14. Dedektör Eklentisi: YARA Kural ve İmza Dedektörü.
    /// YARA kurallarını çalıştırarak bilinen zararlı desenleri, ofset bilgisi ve
    /// kesin kanıt güven derecesiyle tespit eder.
    /// </summary>
    public class YaraDetector : IDetectorPlugin
    {
        private readonly IYaraEngine _yaraEngine;

        public string DetectorId => "Detector.Yara";
        public string DisplayName => "YARA Kural ve İmza Dedektörü";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticSignature;
        public int Priority => 12; // Yüksek öncelikli statik imza tespiti
        public bool IsEnabled { get; set; } = true;

        public YaraDetector(IYaraEngine yaraEngine)
        {
            _yaraEngine = yaraEngine ?? throw new ArgumentNullException(nameof(yaraEngine));
        }

        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var evidenceList = new List<SecurityEvidence>();

            if (string.IsNullOrEmpty(context.FilePath) || !File.Exists(context.FilePath))
            {
                return evidenceList;
            }

            var matches = await _yaraEngine.ScanFileAsync(context.FilePath, cancellationToken);
            if (matches == null || matches.Count == 0)
            {
                return evidenceList;
            }

            foreach (var match in matches)
            {
                var evidence = new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticSignature,
                    SourceDetector = DisplayName,
                    RuleName = $"Yara.{match.RuleName}",
                    Description = $"YARA Kural Eşleşmesi: {match.RuleName} - {match.Description} (Eşleşen Desen Sayısı: {match.MatchedStrings.Count})",
                    ScoreContribution = match.Severity > 0 ? match.Severity : 100, // sev=100
                    Confidence = EvidenceConfidence.Absolute,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256,
                    ProcessId = context.ProcessId,
                    ParentProcessId = context.ParentProcessId
                };

                // String ofsetlerini ve adli analiz ayrıntılarını kanıt metaverisine ekle
                if (match.MatchedStrings.Count > 0)
                {
                    evidence.Metadata["MatchedOffsets"] = string.Join("; ",
                        match.MatchedStrings.Take(10).Select(m => $"{m.Identifier}@0x{m.Offset:X8}"));

                    var firstMatch = match.MatchedStrings[0];
                    evidence.Metadata["PrimaryOffset"] = $"0x{firstMatch.Offset:X8}";
                    evidence.Metadata["PrimaryIdentifier"] = firstMatch.Identifier;
                    evidence.Metadata["TotalMatchedStrings"] = match.MatchedStrings.Count.ToString();
                }

                foreach (var meta in match.Metadata)
                {
                    evidence.Metadata[$"YaraMeta_{meta.Key}"] = meta.Value;
                }

                evidenceList.Add(evidence);
            }

            return evidenceList;
        }
    }
}
