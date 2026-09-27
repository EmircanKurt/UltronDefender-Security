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

        private async Task<SecurityFinding?> AnalyzeCoreAsync(string path, FileInfo fileInfo, string sha256, CancellationToken ct, ArchiveScanResult? archiveResult)
        {
            var context = new DetectionContext
            {
                FilePath = path,
                SHA256 = sha256,
                FileSize = fileInfo.Length,
                ProcessId = 0,
                CorrelationId = Guid.NewGuid().ToString("N")
            };
            context.SharedScan = new ScanContext(path, sha256, fileInfo.Length) { LastWriteTimeUtc = fileInfo.LastWriteTimeUtc };
            if (archiveResult != null) context.Properties["Ultron.ArchiveInspectionResult"] = archiveResult;

            var detectionResult = await _detectionHub.EvaluateAsync(context, ct);

            // Eşik Değeri ve Risk Kararı Haritalaması (Oyun ve geliştirici paket klasörlerinde 85 eşik, genel sistemde 50 eşik)
            int minThreshold = 50; // Directory names never weaken evidence thresholds.
            bool hasExplicitSignature = detectionResult.Evidences.Any(e =>
                e.Category == EvidenceCategory.StaticSignature &&
                e.Confidence == EvidenceConfidence.Absolute &&
                e.ScoreContribution >= 80);
            bool hasConfirmedMalwareEvidence = hasExplicitSignature;
            if (!detectionResult.IsComplete && !hasExplicitSignature)
                throw new IOException($"Dosya analizi tamamlanamadı: {detectionResult.FailedDetectorCount} dedektör hatası. " +
                    string.Join(" ", detectionResult.CoverageLimitations));

            if ((detectionResult.Verdict >= DetectionVerdict.Suspicious && detectionResult.RiskScore >= minThreshold) || hasExplicitSignature)
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
