using System;
using System.IO;
using System.Text.RegularExpressions;
using AegisPC.Core.Helpers;
using AegisPC.Service.Network;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.SmartScreen
{
    public record ZoneAnalysisResult
    {
        public bool HasZoneIdentifier { get; init; }
        public int ZoneId { get; init; } = 0;
        public SecurityZone Zone { get; init; } = SecurityZone.LocalMachine;
        public string? HostUrl { get; init; }
        public string? ReferrerUrl { get; init; }
        public string? HostIpAddress { get; init; }
        public bool IsFromInternet => Zone == SecurityZone.Internet || Zone == SecurityZone.Restricted;
        public bool IsBlockedOrigin { get; init; }
        public string? BlockReason { get; init; }
        public UrlBlockCategory? OriginCategory { get; init; }
        public int RiskScore { get; init; } = 0;
        public string Recommendation { get; init; } = "Güvenli / Yerel dosya.";
    }

    /// <summary>
    /// Windows NTFS Alternate Data Streams (:Zone.Identifier - Mark of the Web / MOTW)
    /// analizcisi ve indirme köken güvenlik denetleyicisi.
    /// İndirilen dosyaların kaynak adresini (HostUrl, ReferrerUrl) yerel kara listelerle
    /// çapraz sorgulayarak C2 ve oltalama kaynaklı zararlı indirmeleri tespit eder.
    /// </summary>
    public class ZoneIdentifierAnalyzer
    {
        private readonly UrlBlocklistManager? _blocklistManager;
        private readonly ILogger<ZoneIdentifierAnalyzer>? _logger;

        private static readonly string[] DangerousDownloadExtensions = {
            ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".iso", ".img", ".vhd", ".msi", ".dll", ".cpl"
        };

        public ZoneIdentifierAnalyzer(
            UrlBlocklistManager? blocklistManager = null,
            ILogger<ZoneIdentifierAnalyzer>? logger = null)
        {
            _blocklistManager = blocklistManager;
            _logger = logger;
        }

        /// <summary>
        /// Belirtilen dosyanın NTFS :Zone.Identifier akışını okur ve köken güvenlik analizini gerçekleştirir.
        /// </summary>
        public ZoneAnalysisResult AnalyzeFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return new ZoneAnalysisResult { HasZoneIdentifier = false };
            }

            string adsPath = filePath + ":Zone.Identifier";
            try
            {
                if (File.Exists(adsPath))
                {
                    string content = File.ReadAllText(adsPath);
                    return ParseZoneIdentifierContent(content, filePath);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Dosyanın Zone.Identifier akışı okunamadı: {Path}", filePath);
            }

            return new ZoneAnalysisResult
            {
                HasZoneIdentifier = false,
                Zone = SecurityZone.LocalMachine,
                ZoneId = 0,
                Recommendation = "Yerel veya MOTW içermeyen dosya."
            };
        }

        /// <summary>
        /// Zone.Identifier INI metin içeriğini ayrıştırıp URL kara listeleriyle çapraz eşleştirir.
        /// </summary>
        public ZoneAnalysisResult ParseZoneIdentifierContent(string content, string? filePath = null)
        {
            if (string.IsNullOrWhiteSpace(content))
            {
                return new ZoneAnalysisResult { HasZoneIdentifier = false };
            }

            int zoneId = 0;
            string? hostUrl = null;
            string? referrerUrl = null;
            string? hostIp = null;

            // ZoneId=3 regex
            var zoneMatch = Regex.Match(content, @"ZoneId\s*=\s*(\d+)", RegexOptions.IgnoreCase);
            if (zoneMatch.Success && int.TryParse(zoneMatch.Groups[1].Value, out int zid))
            {
                zoneId = zid;
            }

            // HostUrl=https://...
            var hostMatch = Regex.Match(content, @"HostUrl\s*=\s*([^\r\n]+)", RegexOptions.IgnoreCase);
            if (hostMatch.Success)
            {
                hostUrl = hostMatch.Groups[1].Value.Trim();
            }

            // ReferrerUrl=https://...
            var refMatch = Regex.Match(content, @"ReferrerUrl\s*=\s*([^\r\n]+)", RegexOptions.IgnoreCase);
            if (refMatch.Success)
            {
                referrerUrl = refMatch.Groups[1].Value.Trim();
            }

            // HostIpAddress=...
            var ipMatch = Regex.Match(content, @"HostIpAddress\s*=\s*([^\r\n]+)", RegexOptions.IgnoreCase);
            if (ipMatch.Success)
            {
                hostIp = ipMatch.Groups[1].Value.Trim();
            }

            var securityZone = zoneId switch
            {
                0 => SecurityZone.LocalMachine,
                1 => SecurityZone.Intranet,
                2 => SecurityZone.Trusted,
                3 => SecurityZone.Internet,
                4 => SecurityZone.Restricted,
                _ => SecurityZone.Unknown
            };

            bool isBlockedOrigin = false;
            string? blockReason = null;
            UrlBlockCategory? category = null;
            int riskScore = 0;

            // 1. URL Kara Liste Çapraz Kontrolü (HostUrl ve ReferrerUrl)
            if (_blocklistManager != null)
            {
                if (!string.IsNullOrEmpty(hostUrl))
                {
                    var eval = _blocklistManager.EvaluateUrl(hostUrl);
                    if (eval.IsBlocked)
                    {
                        isBlockedOrigin = true;
                        blockReason = $"İndirme doğrudan engelli kaynaktan ({eval.Category}): {eval.MatchedPattern}";
                        category = eval.Category;
                        riskScore = Math.Max(riskScore, eval.RiskScore);
                    }
                }

                if (!isBlockedOrigin && !string.IsNullOrEmpty(referrerUrl))
                {
                    var eval = _blocklistManager.EvaluateUrl(referrerUrl);
                    if (eval.IsBlocked)
                    {
                        isBlockedOrigin = true;
                        blockReason = $"İndirme yönlendirici adresi engelli listede ({eval.Category}): {eval.MatchedPattern}";
                        category = eval.Category;
                        riskScore = Math.Max(riskScore, eval.RiskScore);
                    }
                }
            }

            // 2. Tehlikeli Dosya Uzantısı ve İnternet Köken Skoru
            if (!isBlockedOrigin)
            {
                if (securityZone == SecurityZone.Internet || securityZone == SecurityZone.Restricted)
                {
                    riskScore += 30;

                    if (!string.IsNullOrEmpty(filePath))
                    {
                        string ext = Path.GetExtension(filePath).ToLowerInvariant();
                        if (Array.Exists(DangerousDownloadExtensions, e => e == ext))
                        {
                            riskScore += 35; // İnternetten indirilen çalıştırılabilir dosya
                        }
                    }
                }
            }

            string recommendation;
            if (isBlockedOrigin)
            {
                recommendation = "🚨 TEHLİKELİ İNDİRME: Dosya bilinen bir C2 / Oltalama / Zararlı kaynaktan indirilmiştir! Çalıştırılmamalıdır.";
            }
            else if (riskScore >= 60)
            {
                recommendation = "⚠️ ŞÜPHELİ: İnternetten indirilmiş yüksek riskli çalıştırılabilir dosya. Taranmadan açılmamalıdır.";
            }
            else if (zoneId == 3)
            {
                recommendation = "İnternet kaynaklı dosya (Zone 3). Standart güvenlik kontrolleri geçerlidir.";
            }
            else
            {
                recommendation = "Güvenli / Yerel dosya.";
            }

            return new ZoneAnalysisResult
            {
                HasZoneIdentifier = true,
                ZoneId = zoneId,
                Zone = securityZone,
                HostUrl = hostUrl,
                ReferrerUrl = referrerUrl,
                HostIpAddress = hostIp,
                IsBlockedOrigin = isBlockedOrigin,
                BlockReason = blockReason,
                OriginCategory = category,
                RiskScore = Math.Min(riskScore, 100),
                Recommendation = recommendation
            };
        }

        /// <summary>
        /// Dosyadaki :Zone.Identifier akışını silerek dosyanın Windows tarafından engellenmesini (Unblock) kaldırır.
        /// </summary>
        public bool StripZoneIdentifier(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return false;

            try
            {
                string adsPath = filePath + ":Zone.Identifier";
                if (File.Exists(adsPath))
                {
                    File.Delete(adsPath);
                    _logger?.LogInformation("Zone.Identifier başarıyla temizlendi (Unblocked): {Path}", filePath);
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Zone.Identifier silinirken hata: {Path}", filePath);
            }

            return false;
        }

        /// <summary>
        /// Bir dosyaya yapay veya güncel bir :Zone.Identifier akışı iliştirir (Test ve simülasyonlar için).
        /// </summary>
        public bool AttachZoneIdentifier(string filePath, int zoneId = 3, string? hostUrl = null, string? referrerUrl = null)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return false;

            try
            {
                string adsPath = filePath + ":Zone.Identifier";
                var sb = new System.Text.StringBuilder();
                sb.AppendLine("[ZoneTransfer]");
                sb.AppendLine($"ZoneId={zoneId}");
                if (!string.IsNullOrEmpty(hostUrl)) sb.AppendLine($"HostUrl={hostUrl}");
                if (!string.IsNullOrEmpty(referrerUrl)) sb.AppendLine($"ReferrerUrl={referrerUrl}");

                File.WriteAllText(adsPath, sb.ToString());
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Zone.Identifier eklenirken hata: {Path}", filePath);
                return false;
            }
        }
    }
}
