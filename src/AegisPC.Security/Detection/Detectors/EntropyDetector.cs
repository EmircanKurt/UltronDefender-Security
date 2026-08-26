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

            var ext = Path.GetExtension(context.FilePath).ToLowerInvariant();
            
            // Geliştirme kütüphaneleri ve bilinen güvenli yolları entropi anomalisi taramasından muaf tut
            if (AegisPC.Core.Helpers.PathHelper.IsDevelopmentOrPackageDirectory(context.FilePath) ||
                AegisPC.Core.Helpers.PathHelper.IsKnownSafePath(context.FilePath))
            {
                return list;
            }

            // Yalnızca PE ikili yürütülebilirleri (.exe, .dll, .sys, .scr, .ocx, .cpl, .efi) veya uzantısız dosyalar için entropi hesapla
            bool isPeExecutable = ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".scr" || ext == ".ocx" || ext == ".cpl" || ext == ".efi" || string.IsNullOrEmpty(ext);
            if (!isPeExecutable)
            {
                return list;
            }

            double entropy = await EntropyCalculator.CalculateEntropyAsync(context.FilePath, cancellationToken);
            context.Properties["ShannonEntropy"] = entropy;

            bool isGameOrRepack = !string.IsNullOrEmpty(context.FilePath) && 
                (AegisPC.Core.Helpers.PathHelper.IsGameOrRepackDirectory(context.FilePath) || 
                 AegisPC.Core.Helpers.GameCrackClassifier.IsGameCrackOrEmulator(context.FilePath));

            if (entropy >= 7.85)
            {
                int scoreVal = isGameOrRepack ? 10 : 20;
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.EntropyAnomaly,
                    SourceDetector = DisplayName,
                    RuleName = "Entropy.Extreme.PackerOrEncrypted",
                    Description = $"Yüksek Shannon entropisi ({entropy:F2} / 8.0) — Paketlenmiş/Sıkıştırılmış veri",
                    ScoreContribution = scoreVal,
                    Confidence = EvidenceConfidence.Low,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256
                });
            }
            else if (entropy >= 7.50 && !isGameOrRepack)
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.EntropyAnomaly,
                    SourceDetector = DisplayName,
                    RuleName = "Entropy.High.SuspiciousPacking",
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
