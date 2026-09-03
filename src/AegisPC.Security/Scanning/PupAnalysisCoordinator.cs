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
    }

    /// <summary>
    /// Çok katmanlı sezgisel analiz, statik PE yapısı ve eşik haritalamasını yöneten koordinatör sınıfı.
    /// </summary>
    public class PupAnalysisCoordinator : IPupAnalysisCoordinator
    {
        private readonly IDetectionHub _detectionHub;
        private readonly ISecurityFindingService _findingService;

        public PupAnalysisCoordinator(
            IDetectionHub detectionHub,
            ISecurityFindingService findingService)
        {
            _detectionHub = detectionHub;
            _findingService = findingService;
        }

        public async Task<SecurityFinding?> AnalyzeAsync(string path, FileInfo fileInfo, string sha256, bool isGameDir, CancellationToken ct)
        {
            var context = new DetectionContext
            {
                FilePath = path,
                SHA256 = sha256,
                FileSize = fileInfo.Length,
                ProcessId = 0,
                CorrelationId = Guid.NewGuid().ToString("N")
            };

            var detectionResult = await _detectionHub.EvaluateAsync(context, ct);

            // Eşik Değeri ve Risk Kararı Haritalaması (Oyun ve geliştirici paket klasörlerinde 85 eşik, genel sistemde 50 eşik)
            bool isDevDir = PathHelper.IsDevelopmentOrPackageDirectory(path);
            int minThreshold = (isGameDir || isDevDir) ? 85 : 50;
            bool hasExplicitSignature = detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.StaticSignature && e.ScoreContribution >= 80);

            if ((detectionResult.Verdict >= DetectionVerdict.Suspicious && detectionResult.RiskScore >= minThreshold) || hasExplicitSignature)
            {
                RiskLevel riskLevel = detectionResult.RiskScore switch
                {
                    >= 85 => RiskLevel.ConfirmedMalicious,
                    >= 70 => RiskLevel.HighRisk,
                    _ => RiskLevel.Suspicious
                };

                var reasons = detectionResult.Evidences
                    .Select(e => $"[{e.Category}] {e.Description} (+{e.ScoreContribution})")
                    .ToList();

                if (reasons.Count == 0 && !string.IsNullOrEmpty(detectionResult.ThreatTitle))
                {
                    reasons.Add(detectionResult.ThreatTitle);
                }

                FindingCategory findingCat = FindingCategory.SuspiciousLocation;
                if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.StaticSignature))
                    findingCat = FindingCategory.KnownMalwareHash;
                else if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.StaticPeStructure || e.Category == EvidenceCategory.StaticApi))
                    findingCat = FindingCategory.MalwareSuspicion;
                else if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.ScriptHeuristic))
                    findingCat = FindingCategory.SuspiciousScript;
                else if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.Persistence))
                    findingCat = FindingCategory.SuspiciousPersistence;

                string threatTitle = !string.IsNullOrEmpty(detectionResult.ThreatTitle)
                    ? detectionResult.ThreatTitle
                    : (riskLevel == RiskLevel.ConfirmedMalicious ? $"Zararlı Yazılım Tespit Edildi: {fileInfo.Name}" : $"Yüksek Riskli Şüpheli Dosya: {fileInfo.Name}");

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

                await _findingService.AddFindingAsync(finding, ct);
                return finding;
            }

            return null;
        }
    }
}
