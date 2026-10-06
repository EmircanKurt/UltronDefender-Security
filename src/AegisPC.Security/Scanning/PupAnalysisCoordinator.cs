using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// DetectionHub ve PUP/Risk eşik analizi koordinatörü arayüzü.
    /// Kural 7.1 uyarınca dosya adı string karşılaştırmaları yerine doğrulanmış hash,
    /// dijital imza ve davranışsal dedektör göstergelerine dayanır.
    /// </summary>
    public interface IPupAnalysisCoordinator
    {
        /// <summary>
        /// Dosyayı DetectionHub 13 dedektörü üzerinden değerlendirir ve tehdit bulunursa SecurityFinding üretir.
        /// </summary>
        Task<SecurityFinding?> AnalyzeAsync(string path, FileInfo fileInfo, string sha256, bool isGameDir, CancellationToken ct);
        /// <summary>Reuses an actual bounded container inspection while preserving compatibility with other coordinators.</summary>
        Task<SecurityFinding?> AnalyzeArchiveAsync(string path, FileInfo fileInfo, string sha256, ArchiveScanResult archiveResult, CancellationToken ct)
            => AnalyzeAsync(path, fileInfo, sha256, false, ct);
        /// <summary>Shares typed structural identity and a completed archive inspection without changing legacy coordinators.</summary>
        Task<SecurityFinding?> AnalyzeContentAsync(string path, FileInfo fileInfo, string sha256,
            FileContentClassification classification, ArchiveScanResult? archiveResult, CancellationToken ct)
            => archiveResult != null ? AnalyzeArchiveAsync(path, fileInfo, sha256, archiveResult, ct) : AnalyzeAsync(path, fileInfo, sha256, false, ct);
        /// <summary>Returns observed evidence and pipeline completeness independently.</summary>
        async Task<FileContentInspectionResult> AnalyzeContentDetailedAsync(string path, FileInfo fileInfo, string sha256,
            FileContentClassification classification, ArchiveScanResult? archiveResult, CancellationToken ct)
            => new() { Finding = await AnalyzeContentAsync(path, fileInfo, sha256, classification, archiveResult, ct),
                IsComplete = classification.IsComplete && archiveResult?.IsComplete != false,
                CoverageLimitations = classification.CoverageLimitations.ToArray() };
        /// <summary>Inspects the caller-held source while remaining compatible with legacy coordinator implementations.</summary>
        Task<FileContentInspectionResult> AnalyzeLockedContentDetailedAsync(string path, FileInfo fileInfo, string sha256,
            FileContentClassification classification, ArchiveScanResult? archiveResult, Stream source, CancellationToken ct)
            => AnalyzeContentDetailedAsync(path, fileInfo, sha256, classification, archiveResult, ct);
    }

    /// <summary>
    /// Çok katmanlı sezgisel analiz, statik PE yapısı ve eşik haritalamasını yöneten koordinatör sınıfı.
    /// </summary>
    public class PupAnalysisCoordinator : IPupAnalysisCoordinator
    {
        private readonly IDetectionHub _detectionHub;
        private readonly ISecurityFindingService? _findingService;

        public PupAnalysisCoordinator(
            IDetectionHub detectionHub,
            ISecurityFindingService? findingService = null)
        {
            _detectionHub = detectionHub;
            _findingService = findingService;
        }

        /// <summary>Analyzes a stable whole-file identity through the shared detector pipeline.</summary>
        public Task<SecurityFinding?> AnalyzeAsync(string path, FileInfo fileInfo, string sha256, bool isGameDir, CancellationToken ct)
            => AnalyzeCoreAsync(path, fileInfo, sha256, ct, null);

        /// <summary>Passes real member findings and coverage to the hub without decompressing the same container twice.</summary>
        public Task<SecurityFinding?> AnalyzeArchiveAsync(string path, FileInfo fileInfo, string sha256, ArchiveScanResult archiveResult, CancellationToken ct)
            => AnalyzeCoreAsync(path, fileInfo, sha256, ct, archiveResult);

        /// <summary>Passes observed content and explicit coverage to the same detector pipeline used by real-time scans.</summary>
        public Task<SecurityFinding?> AnalyzeContentAsync(string path, FileInfo fileInfo, string sha256,
            FileContentClassification classification, ArchiveScanResult? archiveResult, CancellationToken ct)
            => AnalyzeCoreAsync(path, fileInfo, sha256, ct, archiveResult, classification);

        /// <summary>Retains a confirmed finding without turning incomplete detector or format coverage into success.</summary>
        public async Task<FileContentInspectionResult> AnalyzeContentDetailedAsync(string path, FileInfo fileInfo, string sha256,
            FileContentClassification classification, ArchiveScanResult? archiveResult, CancellationToken ct)
            => await AnalyzeLockedContentDetailedCoreAsync(path, fileInfo, sha256, classification, archiveResult, null, ct);

        /// <summary>Shares stable bytes with detector feature extraction without reopening the path.</summary>
        public Task<FileContentInspectionResult> AnalyzeLockedContentDetailedAsync(string path, FileInfo fileInfo, string sha256,
            FileContentClassification classification, ArchiveScanResult? archiveResult, Stream source, CancellationToken ct)
            => AnalyzeLockedContentDetailedCoreAsync(path, fileInfo, sha256, classification, archiveResult, source, ct);

        private async Task<FileContentInspectionResult> AnalyzeLockedContentDetailedCoreAsync(string path, FileInfo fileInfo, string sha256,
            FileContentClassification classification, ArchiveScanResult? archiveResult, Stream? source, CancellationToken ct)
        {
            DetectionResult? observed = null;
            var finding = await AnalyzeCoreAsync(path, fileInfo, sha256, ct, archiveResult, classification, x => observed = x, source);
            bool complete = observed?.IsComplete == true && classification.IsComplete && archiveResult?.IsComplete != false;
            var limits = (observed?.CoverageLimitations ?? new()).Concat(classification.CoverageLimitations).Distinct().Take(128).ToList();
            if (observed?.FailedDetectorCount > 0) limits.Add("DetectorExecutionFailed");
            if (archiveResult?.IsComplete == false) limits.Add(archiveResult.CoverageLimitation ?? "ArchiveInspectionIncomplete");
            if (!complete && limits.Count == 0) limits.Add("DetectorInspectionIncomplete");
            return new() { Finding = finding, IsComplete = complete, CoverageLimitations = limits.ToArray() };
        }

        private async Task<SecurityFinding?> AnalyzeCoreAsync(string path, FileInfo fileInfo, string sha256, CancellationToken ct,
            ArchiveScanResult? archiveResult, FileContentClassification? classification = null, Action<DetectionResult>? reportCoverage = null, Stream? source = null)
        {
            var context = new DetectionContext
            {
                FilePath = path,
                SHA256 = sha256,
                FileSize = fileInfo.Length,
                ProcessId = 0,
                CorrelationId = Guid.NewGuid().ToString("N")
            };
            context.ContentClassification = classification;
            context.SharedScan = new ScanContext(path, sha256, fileInfo.Length) { LastWriteTimeUtc = fileInfo.LastWriteTimeUtc, ContentClassification = classification, LockedContent = source };
            if (classification != null) context.CoverageLimitations.AddRange(classification.CoverageLimitations);
            if (archiveResult != null) context.Properties["Ultron.ArchiveInspectionResult"] = archiveResult;

            var detectionResult = await _detectionHub.EvaluateAsync(context, ct);
            reportCoverage?.Invoke(detectionResult);

            // Eşik Değeri ve Risk Kararı Haritalaması (Oyun ve geliştirici paket klasörlerinde 85 eşik, genel sistemde 50 eşik)
            int minThreshold = 50; // Directory names never weaken evidence thresholds.
            bool hasExplicitSignature = detectionResult.Evidences.Any(e =>
                e.Category is EvidenceCategory.StaticSignature or EvidenceCategory.AmsiProvider &&
                e.Confidence == EvidenceConfidence.Absolute &&
                e.ScoreContribution >= 80);
            bool hasConfirmedMalwareEvidence = hasExplicitSignature;
            if (!detectionResult.IsComplete && !hasExplicitSignature && reportCoverage == null)
                throw new IOException($"Dosya analizi tamamlanamadı: {detectionResult.FailedDetectorCount} dedektör hatası. " +
                    string.Join(" ", detectionResult.CoverageLimitations));

            if ((detectionResult.Verdict is DetectionVerdict.Suspicious or DetectionVerdict.HighRisk &&
                 detectionResult.RiskScore >= minThreshold) || hasExplicitSignature)
            {
                RiskLevel riskLevel = hasConfirmedMalwareEvidence
                    ? RiskLevel.ConfirmedMalicious
                    : detectionResult.RiskScore >= 70 ? RiskLevel.HighRisk : RiskLevel.Suspicious;

                var reasons = detectionResult.Evidences
                    .Select(e => $"[{e.Category}] {e.Description} (+{e.ScoreContribution})")
                    .ToList();

                if (reasons.Count == 0 && !string.IsNullOrEmpty(detectionResult.ThreatTitle))
                {
                    reasons.Add(detectionResult.ThreatTitle);
                }

                FindingCategory findingCat = FindingCategory.SuspiciousLocation;
                if (detectionResult.Evidences.Any(e =>
                    e.Category == EvidenceCategory.StaticSignature &&
                    e.Confidence == EvidenceConfidence.Absolute &&
                    e.ScoreContribution > 0))
                    findingCat = FindingCategory.KnownMalwareHash;
                else if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.StaticPeStructure || e.Category == EvidenceCategory.StaticApi))
                    findingCat = FindingCategory.MalwareSuspicion;
                else if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.ScriptHeuristic))
                    findingCat = FindingCategory.SuspiciousScript;
                else if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.Persistence))
                    findingCat = FindingCategory.SuspiciousPersistence;
                else if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.AmsiProvider))
                    findingCat = FindingCategory.MalwareSuspicion;

                string threatTitle = !string.IsNullOrEmpty(detectionResult.ThreatTitle)
                    ? detectionResult.ThreatTitle
                    : (riskLevel == RiskLevel.ConfirmedMalicious ? $"Zararlı Yazılım Tespit Edildi: {fileInfo.Name}" : $"Şüpheli Dosya: {fileInfo.Name}");

                var finding = new SecurityFinding
                {
                    ObjectPath = path,
                    ObjectName = fileInfo.Name,
                    SHA256 = sha256,
                    RiskLevel = riskLevel,
                    RiskScore = detectionResult.RiskScore,
                    Category = findingCat,
                    Title = threatTitle,
                    Description = string.Join(" | ", detectionResult.Evidences.Take(2).Select(e => e.Description)),
                    RiskReasons = reasons,
                    ConfidenceLevel = detectionResult.OverallConfidence == EvidenceConfidence.Absolute || detectionResult.OverallConfidence == EvidenceConfidence.High
                        ? ConfidenceLevel.High
                        : ConfidenceLevel.Medium,
                    FirstObserved = DateTime.UtcNow,
                    LastObserved = DateTime.UtcNow,
                    Status = FindingStatus.Active
                };

                if (_findingService != null)
                {
                    await _findingService.AddFindingAsync(finding, ct);
                }
                return finding;
            }

            return null;
        }
    }
}
