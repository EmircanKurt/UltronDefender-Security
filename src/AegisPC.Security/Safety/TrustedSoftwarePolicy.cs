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
    /// Publisher reputation is supporting evidence, never proof of safety.
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
            "VideoLAN",
            "Python Software Foundation",
            "Node.js",
            "Rust Foundation",
            "Docker",
            "Git for Windows",
            "PostgreSQL",
            "Canonical",
            "Wireshark",
            "Atlassian",
            "VMware",
            "Red Hat",
            "Brave Software",
            "Opera Software",
            "7-Zip",
            "Igor Pavlov"
        };

        /// <summary>
        /// Sertifikada adı geçen yayımcının bilinen güvenilir bir teknoloji/yazılım şirketi olup olmadığını doğrular.
        /// </summary>
        public static bool IsTrustedCommercialPublisher(string? publisher)
        {
            if (string.IsNullOrWhiteSpace(publisher)) return false;

            foreach (var trusted in KnownTrustedPublishers)
            {
                // Match complete simple names only, never arbitrary distinguished-name text.
                if (IsExactPublisherMatch(publisher, trusted))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Matches a complete simple publisher name against explicit aliases; never accepts substrings.
        /// </summary>
        private static bool IsExactPublisherMatch(string publisher, string trustedName)
        {
            // This API accepts the certificate's simple publisher name, not a DN or substring.
            if (string.Equals(publisher.Trim(), trustedName, StringComparison.OrdinalIgnoreCase))
                return true;
            var aliases = trustedName switch
            {
                "Microsoft" => new[] { "Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Windows Operating System" },
                "Google" => new[] { "Google LLC", "Google Inc.", "Google Inc" },
                "Valve" => new[] { "Valve Corporation", "Valve Corp." },
                "Mozilla" => new[] { "Mozilla Corporation", "Mozilla Foundation" },
                "NVIDIA" => new[] { "NVIDIA Corporation", "NVIDIA Corp" },
                "Discord" => new[] { "Discord Inc.", "Discord Inc" },
                "Spotify" => new[] { "Spotify AB", "Spotify Ltd" },
                "Epic Games" => new[] { "Epic Games, Inc.", "Epic Games Inc.", "Epic Games Inc" },
                "Docker" => new[] { "Docker Inc", "Docker Inc." },
                "Node.js" => new[] { "Node.js Foundation" },
                "Atlassian" => new[] { "Atlassian Pty Ltd" },
                "Wireshark" => new[] { "Wireshark Foundation" },
                "Apple" => new[] { "Apple Inc.", "Apple Inc" },
                "Adobe" => new[] { "Adobe Inc.", "Adobe Systems Incorporated" },
                "Intel" => new[] { "Intel Corporation", "Intel Corp" },
                _ => Array.Empty<string>()
            };
            return Array.Exists(aliases, alias => string.Equals(publisher.Trim(), alias, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Dosyanın Microsoft / Windows işletim sistemi çekirdek veya sistem bileşeni olup olmadığını doğrular.
        /// </summary>
        public static bool IsTrustedOsPublisher(string? publisher)
        {
            if (string.IsNullOrWhiteSpace(publisher)) return false;

            return IsExactPublisherMatch(publisher, "Microsoft") ||
                   IsExactPublisherMatch(publisher, "Windows");
        }

        /// <summary>
        /// Yazma korumalı veya yetkili kurulum klasörlerini doğrular.
        /// </summary>
        public static bool IsLegitimateInstallLocation(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;

            try
            {
                if (!Path.IsPathFullyQualified(path)) return false;
                var fullPath = Path.GetFullPath(path);

                // Downloads ve Temp meşru kurulum klasörü değildir (Drop Zone)
                if (fullPath.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase) ||
                    fullPath.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) ||
                    fullPath.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // 1. Standart Windows ve Program Files klasörleri
                foreach (var folder in new[] {
                    Environment.SpecialFolder.Windows,
                    Environment.SpecialFolder.ProgramFiles,
                    Environment.SpecialFolder.ProgramFilesX86 })
                {
                    var root = Environment.GetFolderPath(folder);
                    if (!string.IsNullOrEmpty(root) && fullPath.StartsWith(
                        Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar,
                        StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                System.Diagnostics.Trace.TraceWarning("Invalid installation path: {0}", ex.Message);
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
                // Publisher and location never establish a clean verdict.
                result.IsOsComponent = true;
                result.TrustScoreDiscount = -10;
                result.Reason = $"Doğrulanmış Microsoft sistem bileşeni: '{publisher}'";
                return result;
            }

            // 2. Doğrulanmış Microsoft imzası kullanıcı çalışma alanında (LOLBin indirimli koruması)
            if (isSigned && isSignatureValid && isOsPublisher)
            {
                result.IsOsComponent = true;
                result.TrustScoreDiscount = -10;
                result.Reason = $"Doğrulanmış Microsoft ikilisi: '{publisher}'";
                return result;
            }

            // 3. Doğrulanmış bilinen ticari yayımcı (Google, Valve, NVIDIA, Mozilla vb.) meşru kurulum klasöründe
            if (isSigned && isSignatureValid && isCommercial && isLegitLocation)
            {
                // Publisher and location never establish a clean verdict.
                result.IsCommercialTrusted = true;
                result.TrustScoreDiscount = -10;
                result.Reason = $"Doğrulanmış güvenilir yayımcı meşru yazılım klasöründe: '{publisher}'";
                return result;
            }

            // 4. Doğrulanmış ticari yayımcı kullanıcı veya indirme alanında (örn. yeni indirilen Chrome/Steam installer)
            if (isSigned && isSignatureValid && isCommercial)
            {
                result.IsCommercialTrusted = true;
                result.TrustScoreDiscount = -10;
                result.Reason = $"Doğrulanmış ticari yayımcı: '{publisher}'";
                return result;
            }

            // 5. Genel geçerli sertifika
            if (isSigned && isSignatureValid)
            {
                result.TrustScoreDiscount = -10;
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
                result.TrustScoreDiscount = 0;
                result.Reason = "Meşru uygulama klasöründe yer alıyor (Program Files / AppData Programs)";
                return result;
            }

            return result;
        }
    }
}
