using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Service.Network;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.SmartScreen
{
    /// <summary>
    /// Tarayıcı ve ağ indirmelerini gerçek zamanlı izleyip denetleyen DownloadGuard servisi.
    /// NTFS :Zone.Identifier akışını, indirme URL'sini ve dosya riskini değerlendirir.
    /// </summary>
    public class DownloadGuard
    {
        private readonly ZoneIdentifierAnalyzer _zoneAnalyzer;
        private readonly ISecurityFindingService? _findingService;
        private readonly IQuarantineService? _quarantineService;
        private readonly ILogger<DownloadGuard>? _logger;

        public ZoneIdentifierAnalyzer ZoneAnalyzer => _zoneAnalyzer;

        public DownloadGuard(
            ZoneIdentifierAnalyzer? zoneAnalyzer = null,
            UrlBlocklistManager? blocklistManager = null,
            ISecurityFindingService? findingService = null,
            IQuarantineService? quarantineService = null,
            ILogger<DownloadGuard>? logger = null)
        {
            _zoneAnalyzer = zoneAnalyzer ?? new ZoneIdentifierAnalyzer(blocklistManager);
            _findingService = findingService;
            _quarantineService = quarantineService;
            _logger = logger;
        }

        /// <summary>
        /// İndirilen bir dosyanın MOTW güvenlik analizini yapar.
        /// Tehlikeli indirme tespit edilirse güvenlik bulgusu (SecurityFinding) oluşturur.
        /// </summary>
        public async Task<DownloadAnalysis> InspectDownloadedFileAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return new DownloadAnalysis
                {
                    FilePath = filePath ?? string.Empty,
                    Verdict = "FileNotFound",
                    AnalyzedAt = DateTime.UtcNow
                };
            }

            var zoneResult = _zoneAnalyzer.AnalyzeFile(filePath);

            string verdict = "Clean";
            if (zoneResult.IsBlockedOrigin)
            {
                verdict = "BlockedMaliciousOrigin";
            }
            else if (zoneResult.RiskScore >= 60)
            {
                verdict = "SuspiciousDownload";
            }
            else if (zoneResult.IsFromInternet)
            {
                verdict = "InternetDownload";
            }

            var analysis = new DownloadAnalysis
            {
                FilePath = filePath,
                DownloadUrl = zoneResult.HostUrl,
                ReferrerUrl = zoneResult.ReferrerUrl,
                ZoneId = zoneResult.ZoneId,
                ReputationScore = 100 - zoneResult.RiskScore,
                Verdict = verdict,
                AnalyzedAt = DateTime.UtcNow
            };

            // Eğer zararlı veya yüksek riskli bir kaynaktan indirilmişse alarm oluştur
            if (zoneResult.IsBlockedOrigin && _findingService != null)
            {
                var finding = new SecurityFinding
                {
                    Id = Guid.NewGuid(),
                    ObjectPath = filePath,
                    ObjectName = Path.GetFileName(filePath),
                    RiskLevel = RiskLevel.ConfirmedMalicious,
                    RiskScore = zoneResult.RiskScore,
                    Category = FindingCategory.MaliciousDownload,
                    Title = "🚨 Zararlı İndirme Kaynağı Engellendi",
                    Description = $"Dosya bilinen bir C2 / Oltalama / Zararlı kaynaktan ({zoneResult.OriginCategory}) indirilmiştir: {zoneResult.HostUrl}",
                    ConfidenceLevel = ConfidenceLevel.High,
                    Status = FindingStatus.Active,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                finding.RiskReasons.Add($"İndirme URL: {zoneResult.HostUrl}");
                if (!string.IsNullOrEmpty(zoneResult.ReferrerUrl))
                {
                    finding.RiskReasons.Add($"Yönlendirici (Referrer): {zoneResult.ReferrerUrl}");
                }
                finding.RiskReasons.Add($"Engelleme Gerekçesi: {zoneResult.BlockReason}");

                try
                {
                    await _findingService.AddFindingAsync(finding);
                    _logger?.LogWarning("DownloadGuard: Zararlı indirme tespit edildi ve alarm üretildi: {Path}", filePath);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "SecurityFinding eklenirken hata oluştu.");
                }
            }

            return analysis;
        }
    }
}
