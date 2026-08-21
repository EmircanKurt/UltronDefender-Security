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

            double entropy = await EntropyCalculator.CalculateEntropyAsync(context.FilePath, cancellationToken);
            context.Properties["ShannonEntropy"] = entropy;

            if (entropy >= 7.85)
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.EntropyAnomaly,
                    SourceDetector = DisplayName,
                    RuleName = "Entropy.Extreme.PackerOrEncrypted",
                    Description = $"Aşırı yüksek Shannon entropisi ({entropy:F2} / 8.0) — Şifrelenmiş veya paketlenmiş yük göstergesi",
                    ScoreContribution = 35,
                    Confidence = EvidenceConfidence.Medium,
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
                    Description = $"Yüksek Shannon entropisi ({entropy:F2} / 8.0)",
                    ScoreContribution = 15,
                    Confidence = EvidenceConfidence.Low,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256
                });
            }

            return list;
        }
    }
}
