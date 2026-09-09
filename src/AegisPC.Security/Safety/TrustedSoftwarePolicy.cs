using System;
using System.Collections.Generic;
using System.IO;
using AegisPC.Core.Helpers;

namespace AegisPC.Security.Safety
{
    /// <summary>
    /// Değerlendirilen dosyanın güvenilirlik ve itibar analiz sonucu.
    /// </summary>
    public class TrustEvaluationResult
    {
        public bool IsFullyTrusted { get; set; }
        public bool IsOsComponent { get; set; }
        public bool IsCommercialTrusted { get; set; }
        public int TrustScoreDiscount { get; set; }
        public string Reason { get; set; } = string.Empty;
    }

    /// <summary>
    /// Meşru ve doğrulanmış ticari yazılımlar, Windows sistem bileşenleri ve
    /// güvenli kurulum yolları için merkezi güven politikası.
    /// Yanlış pozitifleri (False Positives) sıfırlamak üzere tasarlanmıştır.
    /// </summary>
    public static class TrustedSoftwarePolicy
    {
        // Bilinen güvenilir uluslararası yazılım üreticileri ve sertifika yayımcıları
        private static readonly string[] KnownTrustedPublishers = new[]
        {
            "Microsoft",
            "Windows",
            "Google",
            "Mozilla",
            "Valve",
            "Epic Games",
            "NVIDIA",
            "Advanced Micro Devices",
            "AMD",
            "Intel",
            "Adobe",
            "Discord",
            "Spotify",
            "Apple",
            "JetBrains",
            "GitHub",
            "Oracle",
            "Amazon",
            "Electronic Arts",
            "Ubisoft",
            "Battle.net",
            "Blizzard",
            "Cisco",
            "Zoom Video",
            "Slack Technologies",
            "Telegram",
            "Notepad++",
            "VideoLAN"
        };

        /// <summary>
        /// Sertifikada adı geçen yayımcının bilinen güvenilir bir teknoloji/yazılım şirketi olup olmadığını doğrular.
        /// </summary>
        public static bool IsTrustedCommercialPublisher(string? publisher)
        {
            if (string.IsNullOrWhiteSpace(publisher)) return false;

            foreach (var trusted in KnownTrustedPublishers)
            {
                if (publisher.Contains(trusted, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Dosyanın Microsoft / Windows işletim sistemi çekirdek veya sistem bileşeni olup olmadığını doğrular.
        /// </summary>
        public static bool IsTrustedOsPublisher(string? publisher)
        {
            if (string.IsNullOrWhiteSpace(publisher)) return false;

            return publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                   publisher.Contains("Windows", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Yazma korumalı veya yetkili kurulum klasörlerini doğrular.
        /// </summary>
        public static bool IsLegitimateInstallLocation(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;

            if (PathHelper.IsSystemPath(path)) return true;

            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            if (!string.IsNullOrEmpty(pf) && path.StartsWith(pf, StringComparison.OrdinalIgnoreCase))
                return true;

            if (!string.IsNullOrEmpty(pf86) && path.StartsWith(pf86, StringComparison.OrdinalIgnoreCase))
                return true;

            // Kullanıcı bazlı meşru modern kurulum dizinleri (Chrome, VS Code, Discord, Slack vb.)
            if (path.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase) ||
                path.Contains(@"\AppData\Local\Microsoft\WindowsApps\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Dosyanın Microsoft imzalı doğrulanmış bir Windows sistem bileşeni olup olmadığını kontrol eder.
        /// </summary>
        public static bool IsMicrosoftSignedSystem(string path, string? publisher, bool isSigned, bool isSignatureValid)
        {
            if (!isSigned || !isSignatureValid) return false;
            if (!IsTrustedOsPublisher(publisher)) return false;
            return PathHelper.IsSystemPath(path) || IsLegitimateInstallLocation(path);
        }

        /// <summary>
        /// Dosyanın Program Files altında yer alan doğrulanmış ticari bir yayımcıya ait olup olmadığını kontrol eder.
        /// </summary>
        public static bool IsProgramFilesCommercialSigned(string path, string? publisher, bool isSigned, bool isSignatureValid)
        {
            if (!isSigned || !isSignatureValid) return false;
            if (!IsTrustedCommercialPublisher(publisher)) return false;
            return IsLegitimateInstallLocation(path);
        }

        /// <summary>
        /// Dijital imza, dosya konumu ve yayımcı bilgisine göre bütünleşik güven analizi yapar.
        /// </summary>
        public static TrustEvaluationResult EvaluateTrust(
            string path,
            string? publisher,
            bool isSigned,
            bool isSignatureValid,
            bool isKnownLocation)
        {
            var result = new TrustEvaluationResult();

            bool isOsPublisher = IsTrustedOsPublisher(publisher);
            bool isCommercial = IsTrustedCommercialPublisher(publisher);
            bool isLegitLocation = isKnownLocation || IsLegitimateInstallLocation(path);

            // 1. Doğrulanmış Microsoft OS bileşeni meşru sistem veya program klasöründe
            if (isSigned && isSignatureValid && isOsPublisher && isLegitLocation)
            {
                result.IsFullyTrusted = true;
                result.IsOsComponent = true;
                result.TrustScoreDiscount = -100;
                result.Reason = $"Doğrulanmış Microsoft sistem bileşeni: '{publisher}'";
                return result;
            }

            // 2. Doğrulanmış Microsoft imzası kullanıcı çalışma alanında (LOLBin indirimli koruması)
            if (isSigned && isSignatureValid && isOsPublisher)
            {
                result.IsOsComponent = true;
                result.TrustScoreDiscount = -60;
                result.Reason = $"Doğrulanmış Microsoft ikilisi: '{publisher}'";
                return result;
            }

            // 3. Doğrulanmış bilinen ticari yayımcı (Google, Valve, NVIDIA, Mozilla vb.) meşru kurulum klasöründe
            if (isSigned && isSignatureValid && isCommercial && isLegitLocation)
            {
                result.IsFullyTrusted = true;
                result.IsCommercialTrusted = true;
                result.TrustScoreDiscount = -80;
                result.Reason = $"Doğrulanmış güvenilir yayımcı meşru yazılım klasöründe: '{publisher}'";
                return result;
            }

            // 4. Doğrulanmış ticari yayımcı kullanıcı veya indirme alanında (örn. yeni indirilen Chrome/Steam installer)
            if (isSigned && isSignatureValid && isCommercial)
            {
                result.IsCommercialTrusted = true;
                result.TrustScoreDiscount = -50;
                result.Reason = $"Doğrulanmış ticari yayımcı: '{publisher}'";
                return result;
            }

            // 5. Genel geçerli sertifika
            if (isSigned && isSignatureValid)
            {
                result.TrustScoreDiscount = -40;
                result.Reason = $"Geçerli dijital imza: '{publisher ?? "Bilinmeyen Yayımcı"}'";
                return result;
            }

            // 6. İmzası geçerli olmayan / bozuk dosya
            if (isSigned && !isSignatureValid)
            {
                result.TrustScoreDiscount = 30; // Bozuk sertifika risk artırıcıdır
                result.Reason = "Geçersiz veya tahrif edilmiş dijital sertifika";
                return result;
            }

            // 7. Meşru yazılım kurulum klasöründeki imzasız dosya (daha düşük şüphe)
            if (isLegitLocation)
            {
                result.TrustScoreDiscount = -20;
                result.Reason = "Meşru uygulama klasöründe yer alıyor (Program Files / AppData Programs)";
                return result;
            }

            return result;
        }
    }
}
