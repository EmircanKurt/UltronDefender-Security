using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.Detection.Detectors
{
    /// <summary>
    /// Evaluates local YARA rules as heuristic evidence, retaining matched offsets.
    /// Only independently verified complete canonical test content receives absolute confidence.
    /// </summary>
    public class YaraDetector : IDetectorPlugin
    {
        private readonly IYaraEngine _yaraEngine;

        public string DetectorId => "Detector.Yara";
        public string DisplayName => "YARA Kural ve İmza Dedektörü";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticSignature;
        public int Priority => 12; // Yüksek öncelikli statik imza tespiti
        public bool IsEnabled { get; set; } = true;

        /// <summary>Creates a rule detector; rule names and metadata never establish absolute malware certainty.</summary>
        public YaraDetector(IYaraEngine yaraEngine)
        {
            _yaraEngine = yaraEngine ?? throw new ArgumentNullException(nameof(yaraEngine));
        }

        /// <summary>Evaluates a file and reports rule evidence, incomplete byte coverage and verified canonical test content.</summary>
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

            await using var canonicalStream = new FileStream(context.FilePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            bool isCanonicalTestContent = await IsCanonicalTestContentAsync(canonicalStream, cancellationToken);
            bool isTextDocument = !isCanonicalTestContent &&
                await IsVerifiedTextDocumentAsync(context.FilePath, canonicalStream, cancellationToken);

            foreach (var match in matches)
            {
                EvidenceCategory category;
                EvidenceConfidence confidence;
                int score;
                string group;

                if (isCanonicalTestContent)
                {
                    category = EvidenceCategory.StaticSignature;
                    confidence = EvidenceConfidence.Absolute;
                    score = 100;
                    group = "ExactContentSignature";
                }
                else if (isTextDocument)
                {
                    category = EvidenceCategory.ScriptHeuristic;
                    confidence = EvidenceConfidence.Low;
                    score = Math.Clamp(match.Severity, 1, 15);
                    group = "DocumentationText";
                }
                else
                {
                    category = EvidenceCategory.StaticSignature;
                    confidence = EvidenceConfidence.High;
                    score = Math.Clamp(match.Severity > 0 ? match.Severity : 80, 1, 84);
                    group = "YaraRuleMatch";
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

        private static async Task<bool> IsCanonicalTestContentAsync(Stream stream, CancellationToken cancellationToken)
        {
            const int maximumTestBytes = 128;
            long declaredLength = stream.Length;
            if (declaredLength == 0 || declaredLength > maximumTestBytes) return false;

            byte[] content = new byte[maximumTestBytes + 1];
            int read = 0;
            while (read < content.Length)
            {
                int count = await stream.ReadAsync(content.AsMemory(read), cancellationToken);
                if (count == 0) break;
                read += count;
            }

            return read == declaredLength && stream.Length == declaredLength &&
                MalwareSignatureDatabase.CheckCanonicalTestContent(content.AsSpan(0, read)).IsMatched;
        }

        private static async Task<bool> IsVerifiedTextDocumentAsync(string filePath, Stream stream, CancellationToken cancellationToken)
        {
            string extension = Path.GetExtension(filePath).ToLowerInvariant();
            if (extension is not (".txt" or ".md" or ".rtf" or ".html" or ".htm" or ".log" or ".xml" or
                ".json" or ".csv" or ".tsv" or ".rst" or ".cs" or ".py" or ".c" or ".cpp")) return false;

            const int maximumTextBytes = 1024 * 1024;
            long length = stream.Length;
            if (length == 0 || length > maximumTextBytes) return false;

            stream.Position = 0;
            byte[] content = new byte[checked((int)length)];
            int read = 0;
            while (read < content.Length)
            {
                int count = await stream.ReadAsync(content.AsMemory(read), cancellationToken);
                if (count == 0) return false;
                read += count;
            }
            if (stream.Length != length) return false;

            try
            {
                string text = new UTF8Encoding(false, true).GetString(content);
                return text.All(character => !char.IsControl(character) || character is '\r' or '\n' or '\t' or '\f' or '\uFEFF');
            }
            catch (DecoderFallbackException)
            {
                return false;
            }
        }
    }
}
