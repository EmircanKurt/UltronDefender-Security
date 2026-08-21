using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.BrowserSecurity.Browser
{
    public static class ChromiumExtensionScanner
    {
        private static readonly HashSet<string> HighRiskPermissions = new(StringComparer.OrdinalIgnoreCase)
        {
            "<all_urls>", "http://*/*", "https://*/*", "*://*/*",
            "webRequestBlocking", "debugger", "nativeMessaging", "proxy"
        };

        private static readonly HashSet<string> MediumRiskPermissions = new(StringComparer.OrdinalIgnoreCase)
        {
            "webRequest", "cookies", "tabs", "management", "privacy", "declarativeNetRequest"
        };

        // Known malicious/data-stealing extensions removed from Web Store
        private static readonly HashSet<string> KnownMaliciousExtensionIds = new(StringComparer.OrdinalIgnoreCase)
        {
            "kpiecbbilanbpkndnnllgbghppapbkgh", // Malicious ad-injector
            "fhbjgbiflinjbdggehcddcbncdddomop", // Fake Postman stealer
            "cfhdojbkjhnklbpkdaibdccddilifddb", // Malicious VPN proxy
            "djflhoibgkdhkhhcedjiklpkjnoahfmg", // Cookie logger
            "oboonakemofpalcgghocfoadofidjkkk"  // Malicious screen recorder
        };

        public static List<BrowserProfile> ScanChromiumProfiles(string userDataPath, BrowserType browserType)
        {
            var profiles = new List<BrowserProfile>();
            if (!Directory.Exists(userDataPath)) return profiles;

            try
            {
                var profileDirs = new List<string>();
                var defaultDir = Path.Combine(userDataPath, "Default");
                if (Directory.Exists(defaultDir)) profileDirs.Add(defaultDir);

                // Check "Profile 1", "Profile 2", etc.
                profileDirs.AddRange(Directory.GetDirectories(userDataPath, "Profile *"));

                foreach (var profileDir in profileDirs)
                {
                    var profileName = Path.GetFileName(profileDir);
                    var extensions = ScanExtensionsInProfile(profileDir);

                    profiles.Add(new BrowserProfile
                    {
                        BrowserType = browserType,
                        ProfileName = profileName,
                        ProfilePath = profileDir,
                        Extensions = extensions
                    });
                }
            }
            catch { }

            return profiles;
        }

        private static List<BrowserExtension> ScanExtensionsInProfile(string profileDir)
        {
            var extensions = new List<BrowserExtension>();
            var extDir = Path.Combine(profileDir, "Extensions");
            if (!Directory.Exists(extDir)) return extensions;

            try
            {
                foreach (var extensionIdDir in Directory.GetDirectories(extDir))
                {
                    var extId = Path.GetFileName(extensionIdDir);

                    // Extension versions are subdirectories
                    var versionDirs = Directory.GetDirectories(extensionIdDir);
                    if (versionDirs.Length == 0) continue;

                    var latestVersionDir = versionDirs.OrderByDescending(d => d).First();
                    var manifestPath = Path.Combine(latestVersionDir, "manifest.json");

                    if (File.Exists(manifestPath))
                    {
                        var ext = ParseManifest(extId, manifestPath);
                        if (ext != null)
                        {
                            extensions.Add(ext);
                        }
                    }
                }
            }
            catch { }

            return extensions;
        }

        private static BrowserExtension? ParseManifest(string id, string manifestPath)
        {
            try
            {
                var json = File.ReadAllText(manifestPath);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                string name = root.TryGetProperty("name", out var n) ? n.GetString() ?? id : id;
                string version = root.TryGetProperty("version", out var v) ? v.GetString() ?? "1.0" : "1.0";
                string description = root.TryGetProperty("description", out var d) ? d.GetString() ?? string.Empty : string.Empty;
                string? updateUrl = root.TryGetProperty("update_url", out var u) ? u.GetString() : null;

                // Handle localization placeholders like __MSG_appName__
                if (name.StartsWith("__MSG_"))
                {
                    name = id;
                }

                var permissions = new List<string>();
                if (root.TryGetProperty("permissions", out var perms) && perms.ValueKind == JsonValueKind.Array)
                {
                    foreach (var p in perms.EnumerateArray())
                    {
                        var permStr = p.GetString();
                        if (!string.IsNullOrEmpty(permStr)) permissions.Add(permStr);
                    }
                }

                // Check sideloading (Official Chrome webstore: clients2.google.com/service/update2/crx)
                bool isSideloaded = string.IsNullOrEmpty(updateUrl) ||
                    (!updateUrl.Contains("google.com", StringComparison.OrdinalIgnoreCase) &&
                     !updateUrl.Contains("microsoft.com", StringComparison.OrdinalIgnoreCase));

                var riskReasons = new List<string>();
                int riskScore = 0;

                // 1. Known Malicious Extension ID Matching
                if (KnownMaliciousExtensionIds.Contains(id))
                {
                    riskScore += 90;
                    riskReasons.Add("🚨 DİKKAT: Bilinen zararlı/veri sızdıran eklenti veritabanında tespit edildi. Derhal kaldırılmalıdır.");
                }

                // 2. Sideloaded / Non-Webstore Extension Penalty
                if (isSideloaded)
                {
                    riskScore += 30;
                    riskReasons.Add("Eklenti resmi mağaza dışından (sideloaded / harici kaynak) yüklenmiş.");
                }

                // 3. Permission Combinations Check (e.g. all_urls + webRequestBlocking + cookies = Data Stealer pattern)
                bool hasAllUrls = permissions.Any(p => p.Equals("<all_urls>", StringComparison.OrdinalIgnoreCase) || p.Contains("*://*/*"));
                bool hasWebRequest = permissions.Any(p => p.Contains("webRequest", StringComparison.OrdinalIgnoreCase));
                bool hasCookies = permissions.Any(p => p.Equals("cookies", StringComparison.OrdinalIgnoreCase));

                if (hasAllUrls && hasWebRequest && hasCookies)
                {
                    riskScore += 45;
                    riskReasons.Add("Yüksek Tehlike Kombinasyonu: Tüm URL'ler + Ağ İsteği Engelleme + Çerez Erişimi. Oturum çalma ve kimlik avı riski.");
                }
                else
                {
                    int highRiskCount = permissions.Count(p => HighRiskPermissions.Contains(p));
                    if (highRiskCount > 0)
                    {
                        riskScore += 35;
                        riskReasons.Add($"Geniş yetkili izinler talep ediyor ({string.Join(", ", permissions.Where(p => HighRiskPermissions.Contains(p)).Take(3))}). Tüm web trafiğini okuma veya değiştirme yetkisine sahip olabilir.");
                    }

                    int medRiskCount = permissions.Count(p => MediumRiskPermissions.Contains(p));
                    if (medRiskCount > 0)
                    {
                        riskScore += 15;
                        riskReasons.Add($"Hassas izinler: {string.Join(", ", permissions.Where(p => MediumRiskPermissions.Contains(p)).Take(3))}");
                    }
                }

                riskScore = Math.Clamp(riskScore, 0, 100);

                RiskLevel riskLevel = riskScore switch
                {
                    >= 75 => RiskLevel.ConfirmedMalicious,
                    >= 50 => RiskLevel.HighRisk,
                    >= 30 => RiskLevel.Suspicious,
                    >= 15 => RiskLevel.LowRisk,
                    _ => RiskLevel.Clean
                };

                return new BrowserExtension
                {
                    Id = id,
                    Name = name,
                    Version = version,
                    Description = description,
                    Permissions = permissions,
                    IsEnabled = true,
                    IsSideloaded = isSideloaded,
                    UpdateUrl = updateUrl,
                    ManifestPath = manifestPath,
                    RiskLevel = riskLevel,
                    RiskReasons = riskReasons
                };
            }
            catch
            {
                return null;
            }
        }
    }
}
