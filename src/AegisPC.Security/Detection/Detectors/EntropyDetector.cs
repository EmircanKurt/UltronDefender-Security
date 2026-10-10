using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.Detection.Detectors
{
    public class EntropyDetector : IDetectorPlugin
    {
        public string DetectorId => "Detector.Entropy";
        public string DisplayName => "Shannon Entropi ve Crypter Analizörü";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.EntropyAnomaly;
        public int Priority => 15; // Fast path
        public bool IsEnabled { get; set; } = true;

        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();
            if (string.IsNullOrEmpty(context.FilePath) || !File.Exists(context.FilePath))
            {
                return list;
            }

            // File structure, not a name or directory, determines applicability.
            if (context.ContentClassification?.Formats.Contains(AegisPC.Core.Models.FileContentFormat.PortableExecutable) != true)
            {
                return list;
            }

            double entropy = await EntropyCalculator.CalculateEntropyAsync(context.FilePath, cancellationToken);
            context.Properties["ShannonEntropy"] = entropy;

            if (entropy >= 7.85)
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.EntropyAnomaly,
                    SourceDetector = DisplayName,
                    RuleName = "Entropy.Extreme.PackerOrEncrypted",
                    FeatureIdentity = "PE.Entropy",
                    Nature = EvidenceNature.Capability,
                    Description = $"Yüksek Shannon entropisi ({entropy:F2} / 8.0) — Paketlenmiş/Sıkıştırılmış veri",
                    ScoreContribution = 20,
                    Confidence = EvidenceConfidence.Low,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256
                });
            }
            else if (entropy >= 7.50)
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.EntropyAnomaly,
                    SourceDetector = DisplayName,
                    RuleName = "Entropy.High.SuspiciousPacking",
                    FeatureIdentity = "PE.Entropy",
                    Nature = EvidenceNature.Capability,
                    Description = $"Shannon entropisi ({entropy:F2} / 8.0)",
                    ScoreContribution = 10,
                    Confidence = EvidenceConfidence.Low,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256
                });
            }

            return list;
        }
    }
}
