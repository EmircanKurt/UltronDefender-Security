using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Detection
{
    /// <summary>
    /// Orchestrates independent detectors and produces an explainable, category-bounded security decision.
    /// Positive evidence cannot be erased by signatures, rule-name text, locations, or negative reputation scores.
    /// Exact signature evidence retains priority; failed or partial inspection cannot establish a clean verdict.
    /// </summary>
    public class DetectionHub : IDetectionHub
    {
        private readonly List<IDetectorPlugin> _detectors = new();
        private readonly object _lock = new();
        private readonly ILogger? _logger;
        private int _failedDetectorCount;

        /// <summary>
        /// Returns the failed-detector count of the last completed evaluation; concurrent evaluations carry their own result count.
        /// </summary>
        public int FailedDetectorCount => _failedDetectorCount;

        // Kategori Başına Puan Tavanı (Category Score Caps)
        // Tek bir kategorideki sinyallerin (örn. 5 adet API) tek başına sistemi yanıltmasını engeller
        private static readonly Dictionary<EvidenceCategory, int> CategoryCaps = new()
        {
            [EvidenceCategory.StaticSignature] = 100,
            [EvidenceCategory.AmsiProvider] = 100,
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
            [EvidenceCategory.DigitalCertificate] = 10,
            [EvidenceCategory.MachineLearningHeuristic] = 75
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

        private readonly IExclusionService? _exclusionService;

        public DetectionHub(
            IEnumerable<IDetectorPlugin>? initialDetectors = null,
            ILogger<DetectionHub>? logger = null,
            IExclusionService? exclusionService = null)
        {
            _logger = logger;
            _exclusionService = exclusionService;
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

        /// <summary>Evaluates enabled detectors, preserving positive evidence and returning explicit incomplete coverage; cancellation propagates.</summary>
        public async Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            cancellationToken.ThrowIfCancellationRequested();

            // Kontrol Noktası (b): İstisna (Exclusion) Kontrolü (Dedektörler çalıştırılmadan ÖNCE)
            // User exclusions never suppress a verified exact signature already in the local feed.
            bool knownHash = Scanning.MalwareSignatureDatabase.HasLoadedHash(context.SHA256);
            bool policyBypass = !knownHash && (context.IsUserExcluded ||
                _exclusionService?.IsExcluded(context.FilePath, context.SHA256) == true);
            if (policyBypass) context.CoverageLimitations.Add("UserExclusion: deep analysis was skipped, not certified clean.");

            var stopwatch = Stopwatch.StartNew();
            var rawEvidences = new List<SecurityEvidence>();
            int failedDetectorCount = 0;
            context.SharedScan ??= new ScanContext(context.FilePath, context.SHA256, context.FileSize);

            List<IDetectorPlugin> activeDetectors;
            lock (_lock)
            {
                activeDetectors = _detectors.Where(d => d.IsEnabled && (!policyBypass ||
                    d.PrimaryCategory is EvidenceCategory.StaticSignature or EvidenceCategory.AmsiProvider)).OrderBy(d => d.Priority).ToList();
            }
            if (activeDetectors.Count == 0) context.CoverageLimitations.Add("Etkin dedektör yok.");

            // 1. Run all active detectors
            foreach (var detector in activeDetectors)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    using var detectorMeasurement = Scanning.ScanStageMeasurements.Measure(Scanning.ScanStageTiming.Detector);
                    var detectorEvidences = await detector.EvaluateAsync(context, cancellationToken);
                    if (detectorEvidences != null)
                    {
                        rawEvidences.AddRange(detectorEvidences);
                    }
                }
                catch (OutOfMemoryException) { throw; } // Kritik hatalar yutulmamalı
                catch (StackOverflowException) { throw; }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    // Dedektör izolasyon hatası: Loglama yapılır ancak tarama devam eder
                    failedDetectorCount++;
                    _logger?.LogWarning(ex, "Dedektör '{DetectorName}' başarısız oldu. Tarama diğer dedektörlerle devam ediyor.",
                        detector.GetType().Name);
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Exchange(ref _failedDetectorCount, failedDetectorCount);

            // Fast-Path: Eğer hiçbir dedektör kanıt üretmediyse (Temiz Dosya), 0 bellek tahsisi ile anında dön
            if (rawEvidences.Count == 0)
            {
                stopwatch.Stop();
                return new DetectionResult
                {
                    CorrelationId = context.CorrelationId,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256,
                    Verdict = failedDetectorCount == 0 && context.CoverageLimitations.Count == 0 ? DetectionVerdict.Clean : DetectionVerdict.Unknown,
                    RecommendedPolicy = policyBypass || (failedDetectorCount == 0 && context.CoverageLimitations.Count == 0) ? DetectionPolicy.Allow : DetectionPolicy.Observe,
                    PolicyBypassed = policyBypass,
                    IsComplete = failedDetectorCount == 0 && context.CoverageLimitations.Count == 0,
                    FailedDetectorCount = failedDetectorCount,
                    CoverageLimitations = new List<string>(context.CoverageLimitations),
                    RiskScore = 0,
                    RawScore = 0,
                    DeduplicatedScore = 0,
                    CategoryAdjustedScore = 0,
                    ContextModifier = 1.0,
                    ScoreTrace = failedDetectorCount == 0 && context.CoverageLimitations.Count == 0 ? "No findings in inspected scope" : "Incomplete detector coverage",
                    OverallConfidence = EvidenceConfidence.Low,
                    ThreatTitle = policyBypass ? "Kapsam dışı; kullanıcı istisnası" :
                        failedDetectorCount == 0 && context.CoverageLimitations.Count == 0 ? "İncelenen kapsamda bulgu yok" : "İnceleme tamamlanamadı",
                    Evidences = new List<SecurityEvidence>(),
                    LatencyMs = Math.Round(stopwatch.Elapsed.TotalMilliseconds, 2),
                    ScanTimeUtc = DateTime.UtcNow
                };
            }

            // Independent categories and sources must not erase one another merely by sharing a display rule name.
            var uniqueEvidences = rawEvidences
                .GroupBy(e => (Feature: e.FeatureIdentity.ToUpperInvariant(),
                    Source: e.FeatureIdentity.Length == 0 ? e.SourceDetector : string.Empty,
                    Category: e.FeatureIdentity.Length == 0 ? e.Category : default,
                    Rule: e.FeatureIdentity.Length == 0 ? e.RuleName : string.Empty, e.FilePath,
                    Informational: e.Nature == EvidenceNature.SoftwareClassification))
                .Select(g => g.OrderByDescending(e => e.IsExactMalwareEvidence)
                    .ThenByDescending(e => e.ScoreContribution).ThenByDescending(e => e.Confidence)
                    .ThenByDescending(e => e.Nature != EvidenceNature.Capability)
                    .ThenBy(e => e.Category).ThenBy(e => e.CorrelationGroup, StringComparer.Ordinal)
                    .ThenBy(e => e.SourceDetector, StringComparer.Ordinal).ThenBy(e => e.RuleName, StringComparer.Ordinal)
                    .ThenBy(e => e.Description, StringComparer.Ordinal).First())
                .OrderBy(e => e.Category).ThenBy(e => e.FeatureIdentity, StringComparer.Ordinal)
                .ThenBy(e => e.FilePath, StringComparer.Ordinal).ThenBy(e => e.RuleName, StringComparer.Ordinal)
                .ToList();

            // A source-authenticated tool label is informational, not malware score or action authority.
            var positiveEvidences = uniqueEvidences.Where(e => e.ScoreContribution > 0 && e.Nature != EvidenceNature.SoftwareClassification).ToList();
            bool independentMalware = positiveEvidences.Any(e => e.Nature != EvidenceNature.Capability);
            var optionalMetadata = uniqueEvidences.Where(e => e.Nature == EvidenceNature.SoftwareClassification).Select(e => e.OptionalToolClassification).FirstOrDefault(m =>
                m?.Verified == true && m.ValidUntilUtc > DateTime.UtcNow && !string.IsNullOrWhiteSpace(m.SourceReference) &&
                !string.IsNullOrWhiteSpace(m.IntelVersion) && string.Equals(m.SHA256, context.SHA256, StringComparison.OrdinalIgnoreCase) &&
                context.SHA256 is { Length: 64 } && context.SHA256.All(Uri.IsHexDigit));
            var softwareClass = independentMalware ? AegisPC.Core.Enums.SoftwareFindingClass.MalwareConcern :
                optionalMetadata != null ? AegisPC.Core.Enums.SoftwareFindingClass.PotentiallyUnwantedToolOnly :
                AegisPC.Core.Enums.SoftwareFindingClass.Unclassified;
            int rawScore = positiveEvidences.Sum(e => e.ScoreContribution);

            // 3. Correlation Group Deduplication (Dominant signal + 25% corroboration bonus)
            var groupScores = new Dictionary<(EvidenceCategory Category, string Group), List<SecurityEvidence>>();
            foreach (var evidence in positiveEvidences.Where(e => e.Nature != EvidenceNature.Capability))
            {
                string grpName = string.IsNullOrEmpty(evidence.CorrelationGroup) ? evidence.Category.ToString() : evidence.CorrelationGroup;
                var groupKey = (evidence.Category, grpName.ToUpperInvariant());
                if (!groupScores.TryGetValue(groupKey, out var items))
                {
                    items = new List<SecurityEvidence>();
                    groupScores[groupKey] = items;
                }
                items.Add(evidence);
            }

            var groupEvaluations = new List<(string GroupName, EvidenceCategory Category, int Dominant, int Corroborating, int EffectiveGroupScore)>();
            var capabilityContributions = positiveEvidences.Where(e => e.Nature == EvidenceNature.Capability)
                .Select(e => e.ScoreContribution).OrderByDescending(s => s).ToArray();
            int capabilityScore = Math.Min(25, (capabilityContributions.FirstOrDefault()) + capabilityContributions.Skip(1).Sum() / 4);
            int deduplicatedSum = capabilityScore;

            foreach (var kvp in groupScores.OrderBy(g => g.Key.Category).ThenBy(g => g.Key.Group, StringComparer.Ordinal))
            {
                string grpName = kvp.Key.Group;
                var items = kvp.Value;
                var cat = kvp.Key.Category;

                var independent = items.Where(e => e.Nature != EvidenceNature.Capability).OrderByDescending(e => e.ScoreContribution).ToList();
                int dominantScore = independent.FirstOrDefault()?.ScoreContribution ?? 0;
                int corroboratingSum = independent.Skip(1).Sum(i => i.ScoreContribution);
                int corroborationBonus = (int)Math.Floor(corroboratingSum / 4.0);
                int effectiveGroupScore = dominantScore + corroborationBonus;

                groupEvaluations.Add((grpName, cat, dominantScore, corroboratingSum, effectiveGroupScore));
                deduplicatedSum += effectiveGroupScore;
            }

            // 4. Category Score Capping
            // One global capability pool, outside independent category caps; allocation cannot depend on order.
            int categoryAdjustedScore = capabilityScore;
            var categoryBreakdown = new List<(EvidenceCategory Category, int RawGroupSum, int Cap, int EffectiveScore)>();

            foreach (var catGroup in groupEvaluations.GroupBy(g => g.Category))
            {
                var category = catGroup.Key;
                int sumInCategory = catGroup.Sum(g => g.EffectiveGroupScore);
                int cap = CategoryCaps.TryGetValue(category, out int c) ? c : 100;
                int effectiveScore = Math.Min(sumInCategory, cap);

                categoryBreakdown.Add((category, sumInCategory, cap, effectiveScore));
                categoryAdjustedScore += effectiveScore;
            }

            // Trust is explanatory metadata, not a veto over independent positive security evidence.
            const double contextModifier = 1.0;
            int finalScore = Math.Clamp(categoryAdjustedScore, 0, 100);

            // 6. Build Auditable Score Trace String SADECE riskli/şüpheli bulgular için üretilir
            string scoreTrace = string.Empty;
            if (finalScore > 0 || uniqueEvidences.Count > 0)
            {
                var traceSb = new System.Text.StringBuilder();
                traceSb.AppendLine("=== RISK ENGINE AUDITABLE SCORE TRACE ===");
                traceSb.AppendLine($"Raw Evidence Count: {uniqueEvidences.Count} | Raw Arithmetic Sum: {rawScore}");
                traceSb.AppendLine("\n[Evidence Items]:");
                foreach (var ev in uniqueEvidences)
                {
                    string grp = string.IsNullOrEmpty(ev.CorrelationGroup) ? ev.Category.ToString() : ev.CorrelationGroup;
                    traceSb.AppendLine($" • [{ev.Category}] [{grp}] {ev.RuleName}: {ev.ScoreContribution:+0;-0;0} (Conf: {ev.Confidence}, Trust: {ev.TrustKind}) — {ev.Description}");
                }

                traceSb.AppendLine("\n[Correlation Group Deduplication]:");
                foreach (var g in groupEvaluations)
                {
                    traceSb.AppendLine($" • Group '{g.GroupName}' ({g.Category}): Dominant={g.Dominant}, Corroborating={g.Corroborating} -> Effective = {g.EffectiveGroupScore}");
                }
                traceSb.AppendLine($"Deduplicated Group Sum: {deduplicatedSum}");
                traceSb.AppendLine($"Ordinary capability pool (strongest + other contributions / 4, cap 25): {capabilityScore}");

                traceSb.AppendLine("\n[Category Caps]:");
                foreach (var c in categoryBreakdown)
                {
                    traceSb.AppendLine($" • {c.Category}: GroupSum={c.RawGroupSum}, Cap={c.Cap} -> CategoryScore={c.EffectiveScore}");
                }
                traceSb.AppendLine($"Category Adjusted Sum: {categoryAdjustedScore}");
                traceSb.AppendLine("Negative reputation scores and contextual trust discounts do not subtract positive evidence.");
                traceSb.AppendLine($"FINAL CALCULATED RISK SCORE: {finalScore}/100");
                scoreTrace = traceSb.ToString();
            }

            // 7. Calculate Overall Confidence
            var highestConfidence = positiveEvidences.Count > 0
                ? positiveEvidences.Max(e => e.Confidence)
                : EvidenceConfidence.Low;

            // 8. Determine Verdict and Policy
            var (verdict, policy, threatTitle) = MapVerdictAndPolicy(finalScore, highestConfidence, uniqueEvidences);
            if (verdict == DetectionVerdict.Clean && (failedDetectorCount > 0 || context.CoverageLimitations.Count > 0))
            {
                verdict = DetectionVerdict.Unknown;
                policy = DetectionPolicy.Observe;
                threatTitle = "İnceleme kapsamı eksik";
            }

            stopwatch.Stop();

            return new DetectionResult
            {
                CorrelationId = context.CorrelationId,
                FilePath = context.FilePath,
                SHA256 = context.SHA256,
                Verdict = verdict,
                SoftwareClass = softwareClass,
                SoftwareClassification = optionalMetadata,
                HasIndependentMalwareEvidence = independentMalware,
                PolicyBypassed = policyBypass && verdict != DetectionVerdict.ConfirmedMalicious,
                IsComplete = failedDetectorCount == 0 && context.CoverageLimitations.Count == 0,
                FailedDetectorCount = failedDetectorCount,
                CoverageLimitations = new List<string>(context.CoverageLimitations),
                RecommendedPolicy = policyBypass && verdict != DetectionVerdict.ConfirmedMalicious ? DetectionPolicy.Allow : policy,
                RiskScore = finalScore,
                RawScore = rawScore,
                DeduplicatedScore = deduplicatedSum,
                CategoryAdjustedScore = categoryAdjustedScore,
                ContextModifier = contextModifier,
                ScoreTrace = scoreTrace,
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
            var signatureMatch = evidences.FirstOrDefault(e => e.IsExactMalwareEvidence);
            if (signatureMatch != null)
            {
                return (DetectionVerdict.ConfirmedMalicious, DetectionPolicy.BlockAndQuarantine, signatureMatch.Description);
            }

            // Calibrated multi-signal scoring:
            if (score >= 85)
            {
                bool hasAbsoluteMalwareSignature = evidences.Any(e => e.IsExactMalwareEvidence);

                if (hasAbsoluteMalwareSignature)
                {
                    return (DetectionVerdict.ConfirmedMalicious, DetectionPolicy.BlockAndQuarantine, "Doğrulanmış Zararlı Yazılım / Çoklu Sinyalli Tehdit");
                }

                return (DetectionVerdict.HighRisk, DetectionPolicy.Warn, "Çok Yüksek Sezgisel Risk (Doğrulama Gerekli)");
            }
            if (score >= 70)
            {
                // Sezgisel yüksek risk, kesin zararlı imzası değildir. Kullanıcıya bildir,
                // fakat doğrulanmış bir imza olmadan dosyayı otomatik olarak silme/karantinaya alma.
                return (DetectionVerdict.HighRisk, DetectionPolicy.Warn, "Yüksek Risk / Potansiyel İstenmeyen Tehdit (High Risk)");
            }
            if (score >= 50)
            {
                return (DetectionVerdict.Suspicious, DetectionPolicy.Warn, "Şüpheli Dosya / Çoklu Anomali (Suspicious)");
            }
            if (score >= 30)
            {
                return (DetectionVerdict.LowRisk, DetectionPolicy.Observe, "Düşük Risk / Bilgilendirme (Low Risk)");
            }

            return (DetectionVerdict.Clean, DetectionPolicy.Allow, "İncelenen kapsamda bulgu yok");
        }
    }
}
