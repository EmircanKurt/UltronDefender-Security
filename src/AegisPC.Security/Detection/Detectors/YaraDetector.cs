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
            if (_yaraEngine.MaximumScanBytes is long limit && new FileInfo(context.FilePath).Length > limit)
                context.CoverageLimitations.Add($"YARA yalnız ilk {limit / (1024 * 1024)} MB'ı inceledi.");
            if (matches == null || matches.Count == 0)
            {
                return evidenceList;
            }

            foreach (var match in matches)
            {
                string ext = Path.GetExtension(context.FilePath).ToLowerInvariant();
                bool isDocumentOrText = ext is ".txt" or ".md" or ".doc" or ".docx" or ".pdf" or ".rtf" or ".html" or ".htm" or ".log" or ".xml" or ".json" or ".csv" or ".tsv" or ".rst" or ".cs" or ".py" or ".c" or ".cpp";

                bool isExactEicar = match.RuleName.Contains("EICAR", StringComparison.OrdinalIgnoreCase);
                bool isGenericTextRule = match.RuleName.Contains("Mimikatz", StringComparison.OrdinalIgnoreCase) ||
                                         match.RuleName.Contains("CobaltStrike", StringComparison.OrdinalIgnoreCase);

                EvidenceCategory category;
                EvidenceConfidence confidence;
                int score;
                string group;

                if (isExactEicar)
                {
                    category = EvidenceCategory.StaticSignature;
                    confidence = EvidenceConfidence.Absolute;
                    score = 100;
                    group = "ExactContentSignature";
                }
                else if (isDocumentOrText)
                {
                    // Zararsız metin dokümanları, ders notları veya kaynak kodlarındaki komut sözcükleri (Örn: sekurlsa::logonpasswords)
                    // asla mutlak kanıt veya otomatik karantina sebebi yapılamaz.
                    category = EvidenceCategory.ScriptHeuristic;
                    confidence = EvidenceConfidence.Low;
                    score = Math.Min(15, match.Severity);
                    group = "DocumentationText";
                }
                else if (isGenericTextRule)
                {
                    // Genel Mimikatz / Cobalt Strike metin kuralları mutlak kanıt olmaktan çıkarıldı (Kural P0).
                    // İkililerde yüksek sezgisel gösterge olarak puanlanır ancak tek başına mutlak imza sayılmaz.
                    category = EvidenceCategory.StaticSignature;
                    confidence = EvidenceConfidence.High;
                    score = Math.Min(75, match.Severity > 0 ? match.Severity : 75);
                    group = "HeuristicPattern";
                }
                else
                {
                    bool isDeclaredAbsolute = match.Metadata.TryGetValue("confidence", out var cVal) &&
                                              cVal.Equals("absolute", StringComparison.OrdinalIgnoreCase);

                    category = EvidenceCategory.StaticSignature;
                    confidence = isDeclaredAbsolute ? EvidenceConfidence.Absolute : EvidenceConfidence.High;
                    score = match.Severity > 0 ? match.Severity : 80;
                    group = isDeclaredAbsolute ? "ExactContentSignature" : "YaraRuleMatch";
                }

                var evidence = new SecurityEvidence
                {
                    Category = category,
                    SourceDetector = DisplayName,
                    RuleName = $"Yara.{match.RuleName}",
                    Description = $"YARA Kural Eşleşmesi: {match.RuleName} - {match.Description} (Eşleşen Desen Sayısı: {match.MatchedStrings.Count})",
                    ScoreContribution = score,
                    Confidence = confidence,
                    CorrelationGroup = group,
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
