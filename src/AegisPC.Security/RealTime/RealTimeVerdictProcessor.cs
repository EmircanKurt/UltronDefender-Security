using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı dosya geliş analizi ve risk verdikti üretim arayüzü.
    /// </summary>
    public interface IRealTimeVerdictProcessor
    {
        /// <summary>
        /// Belirtilen dosyayı çok aşamalı (Hash, İmza, Entropi, PE, Sezgisel) olarak denetler ve verdikt üretir.
        /// </summary>
        Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default);

        /// <summary>
        /// Süresi dolan (30 dakikadan eski) verdikt önbellek kayıtlarını temizler.
        /// </summary>
        void CleanupCache();
    }

    /// <summary>
    /// Gerçek zamanlı çok aşamalı (Progressive Analysis) dosya denetim ve risk verdikti motoru.
    /// </summary>
    public class RealTimeVerdictProcessor : IRealTimeVerdictProcessor
    {
        private readonly IHashService _hashService;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IRiskScoringEngine _riskScoringEngine;
        private readonly IFileHashMatcher? _fileHashMatcher;
        private readonly IReputationService? _reputationService;
        private readonly IExclusionService? _exclusionService;
        private readonly ILogger? _logger;
        private readonly IDetectionHub? _detectionHub;
        private readonly IFileContentClassifier _contentClassifier;

        public RealTimeVerdictProcessor(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            ILogger? logger = null)
            : this(hashService, signatureVerifier, riskScoringEngine, null, null, null, logger)
        {
        }

        public RealTimeVerdictProcessor(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IFileHashMatcher? fileHashMatcher,
            ILogger? logger = null)
            : this(hashService, signatureVerifier, riskScoringEngine, fileHashMatcher, null, null, logger)
        {
        }

        public RealTimeVerdictProcessor(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IFileHashMatcher? fileHashMatcher,
            IReputationService? reputationService,
            ILogger? logger = null)
            : this(hashService, signatureVerifier, riskScoringEngine, fileHashMatcher, reputationService, null, logger)
        {
        }

        public RealTimeVerdictProcessor(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IFileHashMatcher? fileHashMatcher,
            IReputationService? reputationService,
            IExclusionService? exclusionService,
            ILogger? logger = null,
            IDetectionHub? detectionHub = null,
            IFileContentClassifier? contentClassifier = null)
        {
            _hashService = hashService;
            _signatureVerifier = signatureVerifier;
            _riskScoringEngine = riskScoringEngine;
            _fileHashMatcher = fileHashMatcher;
            _reputationService = reputationService;
            _exclusionService = exclusionService;
            _logger = logger;
            _detectionHub = detectionHub;
            _contentClassifier = contentClassifier ?? new FileContentClassifier();
        }

        /// <summary>Compatibility hook; unversioned local verdict caching is disabled.</summary>
        public void CleanupCache() { }

        /// <summary>Inspects a locked content identity through shared typed routing; partial inspection is observation, not a clean verdict.</summary>
        public async Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            long policyRevision = DetectionPolicyRevision.Current;
            var scanStart = DateTime.UtcNow;
            var result = new RealTimeVerdictResult
            {
                Verdict = RealTimeVerdict.Clean,
                RecommendedPolicy = RealTimePolicyAction.Allow,
                RiskScore = 0,
                RiskLevel = RiskLevel.Clean,
                ScanStartTime = scanStart
            };

            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                result.Verdict = RealTimeVerdict.Unknown;
                result.RecommendedPolicy = RealTimePolicyAction.Observe;
                result.ThreatDescription = "The file is unavailable; inspection has not completed.";
                result.CoverageLimitations = ["FileUnavailable"];
                result.ScanEndTime = DateTime.UtcNow;
                result.VerdictTime = DateTime.UtcNow;
                return result;
            }

            try
            {
                using var scanLock = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length == 0)
                {
                    result.Verdict = RealTimeVerdict.Unknown;
                    result.RecommendedPolicy = RealTimePolicyAction.Observe;
                    result.CoverageLimitations = ["EmptyFileInspectionSkipped"];
                    result.ThreatDescription = "Empty content; the configured inspection pipeline was not run.";
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                using (ScanStageMeasurements.Measure(ScanStageTiming.Content))
                    result.ContentClassification = await _contentClassifier.ClassifyAsync(scanLock, fileInfo.Extension, ct);
                result.CoverageLimitations = result.ContentClassification.CoverageLimitations.ToArray();

                // STAGE 0: Fast Shared Scan-Cache Lookup (FileHashMatcher)
                string? verifiedHash = null;
                if (_fileHashMatcher != null)
                {
                    var cached = await _fileHashMatcher.TryGetCachedAsync(filePath, fileInfo, ct);
                    verifiedHash = cached.VerifiedHash;
                    // A cache cannot stand in for an unavailable shared engine.
                }

                // STAGE 1: Fast Hash & Signature Database Check
                var sha256 = verifiedHash ?? await _hashService.ComputeSha256Async(filePath, ct);
                ct.ThrowIfCancellationRequested();
                // Compatibility at the old provider boundary; never let a sentinel become a hash/verdict.
                if (sha256 == "VIRUS_INFECTED_OS_BLOCKED")
                    throw new AegisPC.Core.Exceptions.OperatingSystemFileBlockException(AegisPC.Core.Exceptions.OperatingSystemFileBlockKind.ThreatBlocked);
                if (!AegisPC.Contracts.ThreatIntelligence.Sha256Identity.IsValid(sha256))
                    throw new IOException("Content identity is unavailable; no clean or confirmed-malware verdict can be issued.");
                result.SHA256 = sha256;
                result.RuleSetVersion = DetectionRuleSet.Version;



                // Check Known Malware Signatures (EICAR, Ransomware, Droppers, Keyloggers)
                var hashMatch = !string.IsNullOrEmpty(sha256) ? MalwareSignatureDatabase.CheckHash(sha256) : new MalwareSignatureMatch();
                if (!hashMatch.IsMatched)
                {
                    var downloadedMatch = ThreatSignatureDatabase.CheckHash(sha256);
                    if (downloadedMatch.IsMatched)
                        hashMatch = new MalwareSignatureMatch
                        {
                            IsMatched = true, ThreatName = downloadedMatch.Name,
                            ThreatCategory = downloadedMatch.Category, SeverityScore = downloadedMatch.Severity,
                            DetectionMethod = "Verified local threat feed hash"
                        };
                }
                if (hashMatch.IsMatched)
                {
                    result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.99;
                    result.RiskScore = hashMatch.SeverityScore;
                    result.RiskLevel = RiskLevel.ConfirmedMalicious;
                    result.ThreatTitle = $"🚨 Zararlı Yazılım: {hashMatch.ThreatName}";
                    result.ThreatDescription = $"Dosya bilinen tehdit veritabanındaki '{hashMatch.ThreatName}' imzasıyla eşleşti.";
                    result.Evidences.Add($"İmza: {hashMatch.ThreatName} ({hashMatch.ThreatCategory})");
                    result.Evidences.Add($"Tespit Metodu: {hashMatch.DetectionMethod}");
                    result.CoverageLimitations = result.CoverageLimitations.Append("ExactSignatureOnly").Distinct().ToArray();

                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // Hash-bound and explicit path exclusions apply only after the exact local signature check.
                if (_detectionHub == null && _exclusionService?.IsExcluded(filePath, sha256) == true)
                {
                    ApplyUserExclusion(result);
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // Local-only edition: no endpoint hash is sent to a reputation provider.

                if (_detectionHub != null)
                {
                    await InspectWithDetectionHubAsync(result, fileInfo, sha256, scanLock, policyRevision, ct);
                    return result;
                }

                // Check Pattern & YARA-like Rules & API Indicators (EICAR, Keyloggers, Mimikatz, ShadowCopy Deletion)
                var (patternMatch, apiMatches) = await MalwareSignatureDatabase.CheckFileContentAndApisAsync(filePath, ct);
                bool isExactContentSignature = patternMatch.IsMatched &&
                    (patternMatch.DetectionMethod.Equals("Statik İçerik İmzası", StringComparison.OrdinalIgnoreCase) ||
                     patternMatch.ThreatCategory.Equals("TestMalware", StringComparison.OrdinalIgnoreCase));
                if (isExactContentSignature)
                {
                    result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.95;
                    result.RiskScore = patternMatch.SeverityScore;
                    result.RiskLevel = RiskLevel.ConfirmedMalicious;
                    result.ThreatTitle = $"🚨 Şüpheli Kod Deseni: {patternMatch.ThreatName}";
                    result.ThreatDescription = $"Dosya içeriğinde tehlikeli dropper, exploit veya keylogger kodu tespit edildi.";
                    result.Evidences.Add($"Desen: {patternMatch.ThreatName}");
                    result.Evidences.Add($"Metod: {patternMatch.DetectionMethod}");
                    result.CoverageLimitations = result.CoverageLimitations.Append("ExactSignatureOnly").Distinct().ToArray();

                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                result.Verdict = RealTimeVerdict.Unknown;
                result.RiskLevel = RiskLevel.Unknown;
                result.RecommendedPolicy = RealTimePolicyAction.Observe;
                result.InspectionComplete = false;
                result.CoverageLimitations = result.CoverageLimitations.Append("SharedDetectionEngineUnavailable").Distinct().ToArray();
                result.ThreatDescription = "Ortak karar motoru kullanılamadı; eski ad/konum sezgisellerine dönülmedi.";

            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                result.Verdict = RealTimeVerdict.Unknown;
                result.RecommendedPolicy = RealTimePolicyAction.Observe;
                result.InspectionComplete = false;
                result.Retryable = ex is IOException && (ex.HResult & 0xffff) is 32 or 33;
                result.CoverageLimitations = result.CoverageLimitations.Append("InspectionFailed:" + ex.GetType().Name).Distinct().ToArray();
                result.ThreatTitle = "Inspection unavailable";
                if (AegisPC.Core.Exceptions.OperatingSystemFileBlockException.TryGetKind(ex, out var block))
                {
                    result.OperatingSystemBlock = block;
                    result.ThreatTitle = "Windows güvenlik sağlayıcısı erişimi engelledi";
                    result.ThreatDescription = "Dosya Ultron tarafından incelenemedi; sağlayıcı veya zararlı ailesi doğrulanmadı.";
                    result.CoverageLimitations = result.CoverageLimitations.Append("OperatingSystemSecurityBlock").ToArray();
                }
                result.Evidences.Add(ex.GetType().Name);
                _logger?.LogTrace(ex, "Inspection failed for {Path}", filePath);
            }
            finally
            {
                result.ScanEndTime = DateTime.UtcNow;
                result.VerdictTime = DateTime.UtcNow;
            }

            return result;
        }

        private static void ApplyUserExclusion(RealTimeVerdictResult result)
        {
            result.PolicyBypassed = true;
            result.InspectionComplete = false;
            result.Verdict = result.RiskScore >= 50 ? RealTimeVerdict.Suspicious : RealTimeVerdict.Unknown;
            result.RecommendedPolicy = RealTimePolicyAction.Allow;
            result.CoverageLimitations = result.CoverageLimitations.Append("UserExclusion").Distinct().ToArray();
            result.ThreatDescription = "Kullanıcı istisnası nedeniyle inceleme atlandı; temiz olduğu doğrulanmadı.";
        }

        private async Task InspectWithDetectionHubAsync(RealTimeVerdictResult result, FileInfo file, string sha256, Stream source,
            long policyRevision, CancellationToken ct)
        {
            var shared = new ScanContext(file.FullName, sha256, file.Length)
                { LastWriteTimeUtc = file.LastWriteTimeUtc, ContentClassification = result.ContentClassification, LockedContent = source };
            var context = shared.ToDetectionContext();
            context.IsUserExcluded = _exclusionService?.IsExcluded(file.FullName, sha256) == true;
            if (result.ContentClassification != null) context.CoverageLimitations.AddRange(result.ContentClassification.CoverageLimitations);
            var detection = await _detectionHub!.EvaluateAsync(context, ct);
            ct.ThrowIfCancellationRequested();
            result.PolicyBypassed = detection.PolicyBypassed;
            result.SoftwareClass = detection.SoftwareClass;
            result.SoftwareClassification = detection.SoftwareClassification;
            result.HasIndependentMalwareEvidence = detection.HasIndependentMalwareEvidence;
            result.RuleSetVersion = detection.RuleSetVersion;
            result.InspectionComplete = !detection.PolicyBypassed && detection.IsComplete && detection.FailedDetectorCount == 0 && result.ContentClassification?.IsComplete != false;
            result.CoverageLimitations = detection.CoverageLimitations
                .Concat(result.ContentClassification?.CoverageLimitations ?? new())
                .Concat(detection.FailedDetectorCount > 0 ? ["DetectorExecutionFailed"] : Array.Empty<string>()).Distinct().Take(128).ToArray();
            result.RiskScore = detection.RiskScore;
            result.Confidence = detection.OverallConfidence == EvidenceConfidence.Absolute ? 0.99 :
                detection.OverallConfidence == EvidenceConfidence.High ? 0.8 : 0.5;
            result.ThreatTitle = detection.ThreatTitle;
            result.Evidences.AddRange(detection.Evidences.Select(e => $"[{e.Category}] {e.Description}"));
            result.ThreatDescription = string.Join(" | ", detection.Evidences.Take(2).Select(e => e.Description));
            bool exact = detection.Verdict == DetectionVerdict.ConfirmedMalicious && detection.Evidences.Any(e => e.IsExactMalwareEvidence);
            if (exact)
            {
                result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                result.RiskLevel = RiskLevel.ConfirmedMalicious;
                result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
            }
            else if (detection.SoftwareClass == SoftwareFindingClass.PotentiallyUnwantedToolOnly && !detection.HasIndependentMalwareEvidence)
            {
                result.Verdict = result.InspectionComplete ? RealTimeVerdict.Suspicious : RealTimeVerdict.Unknown;
                result.RiskLevel = result.InspectionComplete ? RiskLevel.LowRisk : RiskLevel.Unknown;
                // Records an informational finding only; cannot authorize block/quarantine.
                result.RecommendedPolicy = RealTimePolicyAction.Warn;
            }
            else if (detection.RiskScore >= 50)
            {
                result.Verdict = RealTimeVerdict.Suspicious;
                result.RiskLevel = detection.RiskScore >= 70 ? RiskLevel.HighRisk : RiskLevel.Suspicious;
                result.RecommendedPolicy = detection.PolicyBypassed ? RealTimePolicyAction.Allow : RealTimePolicyAction.Warn;
                if (!result.InspectionComplete)
                    result.ThreatDescription += " | Inspection incomplete: " + string.Join("; ", result.CoverageLimitations);
            }
            else if (!result.InspectionComplete || detection.Verdict == DetectionVerdict.Unknown)
            {
                result.Verdict = RealTimeVerdict.Unknown;
                result.RecommendedPolicy = detection.PolicyBypassed ? RealTimePolicyAction.Allow : RealTimePolicyAction.Observe;
                result.ThreatDescription += " | Inspection incomplete: " + string.Join("; ", result.CoverageLimitations);
                result.Evidences.Add($"Failed detectors: {detection.FailedDetectorCount}");
            }
            else if (detection.Verdict != DetectionVerdict.Clean)
            {
                result.Verdict = RealTimeVerdict.Suspicious;
                result.RiskLevel = RiskLevel.LowRisk;
                result.RecommendedPolicy = RealTimePolicyAction.Observe;
            }
            else
            {
                result.Verdict = RealTimeVerdict.Clean;
                result.RiskLevel = RiskLevel.Clean;
                result.RecommendedPolicy = RealTimePolicyAction.Allow;
                result.ThreatTitle = "İncelenen kapsamda bulgu yok";
                _fileHashMatcher?.SetCache(file.FullName, file.Length, file.LastWriteTimeUtc, null, sha256, false, false, policyRevision);
            }
        }

    }
}
