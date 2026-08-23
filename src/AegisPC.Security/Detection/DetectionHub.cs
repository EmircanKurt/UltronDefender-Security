using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;

namespace AegisPC.Security.Detection
{
    /// <summary>
    /// AegisPC Modüler Detection Hub.
    /// Tüm bağımsız dedektörleri orkestre eder, kanıtları toplar,
    /// kategori bazlı puan tavanı (Category Capping) ve mükerrer kayıt filtrelemesi yaparak
    /// açıklanabilir (Explainable) nihai güvenlik kararını üretir.
    /// </summary>
    public class DetectionHub : IDetectionHub
    {
        private readonly List<IDetectorPlugin> _detectors = new();
        private readonly object _lock = new();

        // Kategori Başına Puan Tavanı (Category Score Caps)
        // Tek bir kategorideki sinyallerin (örn. 5 adet API) tek başına sistemi yanıltmasını engeller
        private static readonly Dictionary<EvidenceCategory, int> CategoryCaps = new()
        {
            [EvidenceCategory.StaticSignature] = 100,
            [EvidenceCategory.AntiEvasion] = 80,
            [EvidenceCategory.ScriptHeuristic] = 50,
            [EvidenceCategory.StaticApi] = 45,
            [EvidenceCategory.StaticPeStructure] = 40,
            [EvidenceCategory.LocationReputation] = 35,
            [EvidenceCategory.EntropyAnomaly] = 35,
            [EvidenceCategory.BehaviorProcess] = 40,
            [EvidenceCategory.BehaviorMemory] = 50,
            [EvidenceCategory.BehaviorNetwork] = 30,
            [EvidenceCategory.Persistence] = 30,
            [EvidenceCategory.ArchiveAnomaly] = 40,
            [EvidenceCategory.DigitalCertificate] = 10
        };

        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors
        {
            get
            {
                lock (_lock)
                {
                    return _detectors.OrderBy(d => d.Priority).ToList();
                }
            }
        }

        public DetectionHub(IEnumerable<IDetectorPlugin>? initialDetectors = null)
        {
            if (initialDetectors != null)
            {
                foreach (var d in initialDetectors)
                {
                    RegisterDetector(d);
                }
            }
        }

        public void RegisterDetector(IDetectorPlugin detector)
        {
            if (detector == null) throw new ArgumentNullException(nameof(detector));

            lock (_lock)
            {
                _detectors.RemoveAll(d => d.DetectorId.Equals(detector.DetectorId, StringComparison.OrdinalIgnoreCase));
                _detectors.Add(detector);
            }
        }

        public bool UnregisterDetector(string detectorId)
        {
            lock (_lock)
            {
                return _detectors.RemoveAll(d => d.DetectorId.Equals(detectorId, StringComparison.OrdinalIgnoreCase)) > 0;
            }
        }

        public async Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));

            var stopwatch = Stopwatch.StartNew();
            var rawEvidences = new List<SecurityEvidence>();

            List<IDetectorPlugin> activeDetectors;
            lock (_lock)
            {
                activeDetectors = _detectors.Where(d => d.IsEnabled).OrderBy(d => d.Priority).ToList();
            }

            // 1. Run all active detectors
            foreach (var detector in activeDetectors)
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    var detectorEvidences = await detector.EvaluateAsync(context, cancellationToken);
                    if (detectorEvidences != null)
                    {
                        rawEvidences.AddRange(detectorEvidences);
                    }
                }
                catch
                {
                    // Isolated plugin fault tolerance: One detector's error does not fail the entire hub
                }
            }

            // 2. Deduplicate Evidence by RuleName and FilePath
            var uniqueEvidences = rawEvidences
                .GroupBy(e => $"{e.RuleName}::{e.FilePath}")
                .Select(g => g.First())
                .ToList();

            int rawScore = uniqueEvidences.Sum(e => e.ScoreContribution);

            // 3. Correlation Group Deduplication (Dominant signal + 25% corroboration bonus)
            var groupScores = new Dictionary<string, (EvidenceCategory Category, int Score, List<SecurityEvidence> Items)>(StringComparer.OrdinalIgnoreCase);
            foreach (var evidence in uniqueEvidences)
            {
                string grpName = string.IsNullOrEmpty(evidence.CorrelationGroup) ? evidence.Category.ToString() : evidence.CorrelationGroup;
                if (!groupScores.TryGetValue(grpName, out var grpEntry))
                {
                    grpEntry = (evidence.Category, 0, new List<SecurityEvidence>());
                    groupScores[grpName] = grpEntry;
                }
                grpEntry.Items.Add(evidence);
            }

            var groupEvaluations = new List<(string GroupName, EvidenceCategory Category, int Dominant, int Corroborating, int EffectiveGroupScore)>();
            int deduplicatedSum = 0;

            foreach (var kvp in groupScores)
            {
                string grpName = kvp.Key;
                var items = kvp.Value.Items;
                var cat = kvp.Value.Category;

                var dominant = items.OrderByDescending(i => i.ScoreContribution).First();
                int dominantScore = dominant.ScoreContribution;
                int corroboratingSum = items.Where(i => i != dominant).Sum(i => i.ScoreContribution);
                int corroborationBonus = (int)Math.Floor(corroboratingSum / 4.0);
                int effectiveGroupScore = dominantScore + corroborationBonus;

                groupEvaluations.Add((grpName, cat, dominantScore, corroboratingSum, effectiveGroupScore));
                deduplicatedSum += effectiveGroupScore;
            }

            // 4. Category Score Capping
            int categoryAdjustedScore = 0;
            var categoryBreakdown = new List<(EvidenceCategory Category, int RawGroupSum, int Cap, int EffectiveScore)>();

            foreach (var catGroup in groupEvaluations.GroupBy(g => g.Category))
            {
                var category = catGroup.Key;
                int sumInCategory = catGroup.Sum(g => g.EffectiveGroupScore);
                int cap = CategoryCaps.TryGetValue(category, out int c) ? c : 100;
                int effectiveScore = sumInCategory >= 0 ? Math.Min(sumInCategory, cap) : sumInCategory;

                categoryBreakdown.Add((category, sumInCategory, cap, effectiveScore));
                categoryAdjustedScore += effectiveScore;
            }

            // 5. Context Modifier (Digital Trust / Safe Path / Game Crack Heuristic Calibration)
            double contextModifier = 1.0;
            bool hasExplicitMalwareSignature = uniqueEvidences.Any(e => e.Category == EvidenceCategory.StaticSignature && e.ScoreContribution >= 80);

            bool isMicrosoftOrSystem = uniqueEvidences.Any(e => 
                e.RuleName.Contains("ValidMicrosoft", StringComparison.OrdinalIgnoreCase) || 
                e.RuleName.Contains("MicrosoftTrusted", StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(context.FilePath) && AegisPC.Core.Helpers.PathHelper.IsSystemPath(context.FilePath));

            bool isCommercialSigned = uniqueEvidences.Any(e => 
                e.RuleName.Contains("TrustedPublisher", StringComparison.OrdinalIgnoreCase) ||
                e.RuleName.Contains("Signature.Valid", StringComparison.OrdinalIgnoreCase) ||
                e.RuleName.Contains("Cert.ValidPublisher", StringComparison.OrdinalIgnoreCase));

            bool isGameCrackOrEmulator = !string.IsNullOrEmpty(context.FilePath) && 
                (AegisPC.Core.Helpers.GameCrackClassifier.IsGameCrackOrEmulator(context.FilePath) || 
                 AegisPC.Core.Helpers.PathHelper.IsGameOrRepackDirectory(context.FilePath));

            if (!hasExplicitMalwareSignature)
            {
                if (isMicrosoftOrSystem)
                {
                    contextModifier = 0.0;
                }
                else if (isCommercialSigned)
                {
                    contextModifier = 0.0;
                }
                else if (!string.IsNullOrEmpty(context.FilePath) && AegisPC.Core.Helpers.PathHelper.IsKnownSafePath(context.FilePath))
                {
                    contextModifier = 0.0;
                }
                else if (isGameCrackOrEmulator)
                {
                    // Zararsız Oyun Crack / Steam Emülatörü / Mod Dosyası: Gerçek malware imzası taşımıyorsa puanı sıfırla (Temiz)
                    contextModifier = 0.0;
                }
            }

            int finalScore = Math.Clamp((int)Math.Floor(categoryAdjustedScore * contextModifier), 0, 100);

            // 6. Build Auditable Score Trace String
            var traceSb = new System.Text.StringBuilder();
            traceSb.AppendLine("=== RISK ENGINE AUDITABLE SCORE TRACE ===");
            traceSb.AppendLine($"Raw Evidence Count: {uniqueEvidences.Count} | Raw Arithmetic Sum: {rawScore}");
            traceSb.AppendLine("\n[Evidence Items]:");
            foreach (var ev in uniqueEvidences)
            {
                string grp = string.IsNullOrEmpty(ev.CorrelationGroup) ? ev.Category.ToString() : ev.CorrelationGroup;
                traceSb.AppendLine($" • [{ev.Category}] [{grp}] {ev.RuleName}: +{ev.ScoreContribution} (Conf: {ev.Confidence}) — {ev.Description}");
            }

            traceSb.AppendLine("\n[Correlation Group Deduplication]:");
            foreach (var g in groupEvaluations)
            {
                traceSb.AppendLine($" • Group '{g.GroupName}' ({g.Category}): Dominant={g.Dominant}, Corroborating={g.Corroborating} -> Effective = {g.EffectiveGroupScore}");
            }
            traceSb.AppendLine($"Deduplicated Group Sum: {deduplicatedSum}");

            traceSb.AppendLine("\n[Category Caps]:");
            foreach (var c in categoryBreakdown)
            {
                traceSb.AppendLine($" • {c.Category}: GroupSum={c.RawGroupSum}, Cap={c.Cap} -> CategoryScore={c.EffectiveScore}");
            }
            traceSb.AppendLine($"Category Adjusted Sum: {categoryAdjustedScore}");
            traceSb.AppendLine($"Context Trust Modifier: {contextModifier:F2}");
            traceSb.AppendLine($"FINAL CALCULATED RISK SCORE: {finalScore}/100");

            // 7. Calculate Overall Confidence
            var highestConfidence = uniqueEvidences.Count > 0
                ? uniqueEvidences.Max(e => e.Confidence)
                : EvidenceConfidence.Low;

            // 8. Determine Verdict and Policy
            var (verdict, policy, threatTitle) = MapVerdictAndPolicy(finalScore, highestConfidence, uniqueEvidences);

            stopwatch.Stop();

            return new DetectionResult
            {
                CorrelationId = context.CorrelationId,
                FilePath = context.FilePath,
                SHA256 = context.SHA256,
                Verdict = verdict,
                RecommendedPolicy = policy,
                RiskScore = finalScore,
                RawScore = rawScore,
                DeduplicatedScore = deduplicatedSum,
                CategoryAdjustedScore = categoryAdjustedScore,
                ContextModifier = contextModifier,
                ScoreTrace = traceSb.ToString(),
                OverallConfidence = highestConfidence,
                ThreatTitle = threatTitle,
                Evidences = uniqueEvidences,
                LatencyMs = Math.Round(stopwatch.Elapsed.TotalMilliseconds, 2),
                ScanTimeUtc = DateTime.UtcNow
            };
        }

        private static (DetectionVerdict verdict, DetectionPolicy policy, string title) MapVerdictAndPolicy(
            int score,
            EvidenceConfidence confidence,
            List<SecurityEvidence> evidences)
        {
            // Exact Signature Match Override
            var signatureMatch = evidences.FirstOrDefault(e => e.Category == EvidenceCategory.StaticSignature && e.ScoreContribution >= 90);
            if (signatureMatch != null)
            {
                return (DetectionVerdict.ConfirmedMalicious, DetectionPolicy.BlockAndQuarantine, signatureMatch.Description);
            }

            // Calibrated multi-signal scoring:
            if (score >= 85)
            {
                return (DetectionVerdict.ConfirmedMalicious, DetectionPolicy.BlockAndQuarantine, "Yüksek Riskli Zararlı Yazılım (Confirmed Malicious)");
            }
            if (score >= 70)
            {
                return (DetectionVerdict.HighRisk, DetectionPolicy.Quarantine, "Yüksek Risk / Potansiyel İstenmeyen Tehdit (High Risk)");
            }
            if (score >= 50)
            {
                return (DetectionVerdict.Suspicious, DetectionPolicy.Warn, "Şüpheli Dosya / Çoklu Anomali (Suspicious)");
            }
            if (score >= 30)
            {
                return (DetectionVerdict.LowRisk, DetectionPolicy.Observe, "Düşük Risk / Bilgilendirme (Low Risk)");
            }

            return (DetectionVerdict.Clean, DetectionPolicy.Allow, "Güvenli / Temiz");
        }
    }
}
