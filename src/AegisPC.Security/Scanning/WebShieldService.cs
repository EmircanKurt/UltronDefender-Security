using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    public class WebShieldRulesStorage
    {
        public List<string> BypassDomains { get; set; } = new();
        public Dictionary<string, string> BlockedDomains { get; set; } = new();
    }

    public class WebShieldService : IWebShieldService
    {
        private readonly ILogger<WebShieldService>? _logger;
        private readonly ConcurrentDictionary<string, string> _blockedDomains = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, byte> _bypassDomains = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _storageFilePath;
        private readonly object _diskLock = new();

        // Curated Top Brand Names targeted by phishing
        private static readonly string[] TargetedBrands = new[]
        {
            "paypal", "microsoft", "google", "apple", "amazon", "netflix", 
            "facebook", "instagram", "binance", "coinbase", "chase", "wellsfargo", 
            "steamcommunity", "discord", "telegram", "whatsapp", "bankofamerica"
        };

        // Official Root Domains for targeted brands
        private static readonly HashSet<string> OfficialBrandDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "paypal.com", "microsoft.com", "live.com", "office.com", "google.com", "apple.com", "icloud.com",
            "amazon.com", "netflix.com", "facebook.com", "instagram.com", "binance.com", "coinbase.com",
            "chase.com", "wellsfargo.com", "steamcommunity.com", "steampowered.com", "discord.com", "discord.gg",
            "telegram.org", "whatsapp.com", "bankofamerica.com", "github.com", "cloudflare.com", "wikipedia.org", "youtube.com"
        };

        // High-risk TLDs frequently abused in automated phishing campaigns
        private static readonly HashSet<string> SuspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
        {
            ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".loan", 
            ".work", ".buzz", ".click", ".rest", ".country", ".stream", ".gdn"
        };

        // Sensitive auth/banking keywords
        private static readonly string[] SensitiveKeywords = new[]
        {
            "login", "verify", "account", "banking", "secure", "password", 
            "signin", "recovery", "wallet", "checkpoint", "auth-token", "billing"
        };

        public WebShieldService(ILogger<WebShieldService>? logger = null)
        {
            _logger = logger;
            var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AegisPC");
            Directory.CreateDirectory(dataDir);
            _storageFilePath = Path.Combine(dataDir, "web_shield_rules.json");

            // Initialize defaults
            _bypassDomains.TryAdd("microsoft.com", 0);
            _bypassDomains.TryAdd("windowsupdate.com", 0);
            _bypassDomains.TryAdd("google.com", 0);
            _bypassDomains.TryAdd("github.com", 0);

            _blockedDomains.TryAdd("paypa1-security-check.com", "Zararlı Phishing & Kimlik Avı");
            _blockedDomains.TryAdd("micros0ft-support-alert.xyz", "Teknik Destek Dolandırıcılığı");
            _blockedDomains.TryAdd("steamcommunity-trade-bot.xyz", "Steam Envanter Hırsızlığı");
            _blockedDomains.TryAdd("update-windows-defender-security.top", "Sahte Güvenlik Güncellemesi");

            LoadRulesFromDisk();
        }

        private void LoadRulesFromDisk()
        {
            lock (_diskLock)
            {
                try
                {
                    if (File.Exists(_storageFilePath))
                    {
                        var json = File.ReadAllText(_storageFilePath);
                        var rules = JsonSerializer.Deserialize<WebShieldRulesStorage>(json);
                        if (rules != null)
                        {
                            if (rules.BypassDomains != null)
                            {
                                foreach (var d in rules.BypassDomains) _bypassDomains.TryAdd(d, 0);
                            }
                            if (rules.BlockedDomains != null)
                            {
                                foreach (var kv in rules.BlockedDomains) _blockedDomains[kv.Key] = kv.Value;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to load WebShield rules from disk.");
                }
            }
        }

        private void SaveRulesToDisk()
        {
            lock (_diskLock)
            {
                try
                {
                    var storage = new WebShieldRulesStorage
                    {
                        BypassDomains = _bypassDomains.Keys.ToList(),
                        BlockedDomains = _blockedDomains.ToDictionary(k => k.Key, v => v.Value)
                    };
                    var json = JsonSerializer.Serialize(storage, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(_storageFilePath, json);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to save WebShield rules to disk.");
                }
            }
        }

        public Task<WebReputationVerdict> AnalyzeUrlAsync(string url, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                return Task.FromResult(new WebReputationVerdict { RiskScore = 0, Host = string.Empty, Url = url });
            }

            var verdict = new WebReputationVerdict { Url = url };
            var normalizedHost = ExtractHost(url);
            verdict.Host = normalizedHost;

            // 1. Whitelist / User Bypass Check
            if (IsBypassedOrTrusted(normalizedHost))
            {
                verdict.RiskScore = 0;
                verdict.IsBlocked = false;
                verdict.Recommendation = "Güvenilir alan adı.";
                return Task.FromResult(verdict);
            }

            // 2. Explicit Blocklist Check
            if (_blockedDomains.TryGetValue(normalizedHost, out var blockReason))
            {
                verdict.RiskScore = 100;
                verdict.IsBlocked = true;
                verdict.IsPhishing = true;
                verdict.DetectionReasons.Add($"Bilinen zararlı/dolandırıcı alan adı veritabanında mevcut: {blockReason}");
                verdict.Recommendation = "Bu web sitesine erişim Ultron Web Kalkanı tarafından tamamen engellendi.";
                return Task.FromResult(verdict);
            }

            int score = 0;

            // 3. Punycode / Homograph Attack Detection (e.g. xn--pple-43d.com)
            if (normalizedHost.StartsWith("xn--", StringComparison.OrdinalIgnoreCase) || normalizedHost.Contains(".xn--", StringComparison.OrdinalIgnoreCase))
            {
                score += 65;
                verdict.IsPhishing = true;
                verdict.DetectionReasons.Add("Punycode / Homograph Taklit Alan Adı Tespiti (IDN Sahteciliği).");
            }

            // 4. IP-direct Access Check
            if (IPAddress.TryParse(normalizedHost, out var ip))
            {
                if (!IsPrivateIp(ip))
                {
                    score += 45;
                    verdict.DetectionReasons.Add("Doğrudan ham IP üzerinden bağlantı kuruluyor (Şüpheli C2 veya açılış sayfası).");
                }
            }

            // 5. High-Risk TLD Check
            var tld = GetTld(normalizedHost);
            if (SuspiciousTlds.Contains(tld))
            {
                score += 25;
                verdict.DetectionReasons.Add($"Yüksek riskli/ücretsiz kötüye kullanılan TLD uzantısı: {tld}");
            }

            // 6. Typo-squatting & Brand Impersonation Heuristics
            foreach (var brand in TargetedBrands)
            {
                if (OfficialBrandDomains.Contains(normalizedHost)) break;

                if (normalizedHost.Contains(brand, StringComparison.OrdinalIgnoreCase))
                {
                    score += 35;
                    verdict.IsPhishing = true;
                    verdict.DetectionReasons.Add($"Popüler marka adı hedefli taklit şüphesi: '{brand}'");
                }
                else
                {
                    var typoRegex = BuildTypoRegex(brand);
                    if (typoRegex.IsMatch(normalizedHost) && !normalizedHost.Equals(brand, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 50;
                        verdict.IsPhishing = true;
                        verdict.DetectionReasons.Add($"Gelişmiş Levenshtein/Karakter taklit şüphesi (Typo-squatting): '{brand}'");
                    }
                }
            }

            // 7. Sensitive Keywords in URL Path/Subdomain
            var lowerUrl = url.ToLowerInvariant();
            int keywordHits = 0;
            foreach (var kw in SensitiveKeywords)
            {
                if (lowerUrl.Contains(kw))
                {
                    keywordHits++;
                }
            }

            if (keywordHits >= 2)
            {
                score += 35;
                verdict.IsPhishing = true;
                verdict.DetectionReasons.Add($"URL içerisinde birden fazla kritik kimlik/ödeme anahtar kelimesi tespit edildi ({keywordHits} eşleşme).");
            }

            // 8. Direct Download of High-Risk Executable from Non-Trusted Source
            if (lowerUrl.EndsWith(".exe") || lowerUrl.EndsWith(".scr") || lowerUrl.EndsWith(".vbs") || lowerUrl.EndsWith(".bat") || lowerUrl.EndsWith(".ps1"))
            {
                score += 35;
                verdict.IsDangerousDownload = true;
                verdict.DetectionReasons.Add("Doğrudan çalıştırılabilir zararlı dosya indirme bağlantısı (.exe / .scr / .script).");
            }

            verdict.RiskScore = Math.Min(score, 100);
            verdict.IsBlocked = verdict.RiskScore >= 60;

            if (verdict.IsBlocked)
            {
                verdict.Recommendation = "⚠️ YÜKSEK RİSK: Bu web sitesi kimlik avı, dolandırıcılık veya zararlı indirme içermektedir. Ziyaret edilmesi önerilmez.";
            }
            else if (verdict.RiskScore >= 30)
            {
                verdict.Recommendation = "ORTA RİSK: Şüpheli URL parametreleri veya alan adı yapısı. Dikkatli olun.";
            }
            else
            {
                verdict.Recommendation = "Düşük riskli veya standart web sayfası.";
            }

            return Task.FromResult(verdict);
        }

        public bool AddBypassDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return false;
            var host = ExtractHost(domain);
            _bypassDomains.TryAdd(host, 0);
            SaveRulesToDisk();
            return true;
        }

        public bool RemoveBypassDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return false;
            var host = ExtractHost(domain);
            var removed = _bypassDomains.TryRemove(host, out _);
            if (removed) SaveRulesToDisk();
            return removed;
        }

        public IReadOnlyList<string> GetBypassDomains() => _bypassDomains.Keys.OrderBy(k => k).ToList();

        public bool AddBlockedDomain(string domain, string reason)
        {
            if (string.IsNullOrWhiteSpace(domain)) return false;
            var host = ExtractHost(domain);
            _blockedDomains[host] = reason;
            SaveRulesToDisk();
            return true;
        }

        public IReadOnlyList<string> GetBlockedDomains() => _blockedDomains.Keys.OrderBy(k => k).ToList();

        private bool IsBypassedOrTrusted(string host)
        {
            if (_bypassDomains.ContainsKey(host)) return true;
            return OfficialBrandDomains.Any(off => host == off || host.EndsWith("." + off));
        }

        private static string ExtractHost(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return string.Empty;
            string clean = url.Trim();

            if (!clean.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !clean.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
                !clean.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase))
            {
                clean = "https://" + clean;
            }

            if (Uri.TryCreate(clean, UriKind.Absolute, out var uri))
            {
                return uri.Host;
            }

            var hostPart = clean.Replace("https://", "").Replace("http://", "").Split('/')[0].Split(':')[0];
            return hostPart;
        }

        private static string GetTld(string host)
        {
            int lastDot = host.LastIndexOf('.');
            if (lastDot >= 0 && lastDot < host.Length - 1)
            {
                return host.Substring(lastDot);
            }
            return string.Empty;
        }

        private static bool IsPrivateIp(IPAddress ip)
        {
            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                if (bytes[0] == 10) return true;
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                if (bytes[0] == 192 && bytes[1] == 168) return true;
                if (bytes[0] == 127) return true;
            }
            return false;
        }

        private static Regex BuildTypoRegex(string brand)
        {
            var sb = new System.Text.StringBuilder();
            foreach (char c in brand.ToLowerInvariant())
            {
                switch (c)
                {
                    case 'o': sb.Append("[o0]"); break;
                    case 'l': sb.Append("[l1i|]"); break;
                    case 'i': sb.Append("[i1l!|]"); break;
                    case 'e': sb.Append("[e3]"); break;
                    case 'a': sb.Append("[a4@]"); break;
                    case 's': sb.Append("[s5$]"); break;
                    case 't': sb.Append("[t7+]"); break;
                    default: sb.Append(Regex.Escape(c.ToString())); break;
                }
            }
            return new Regex(sb.ToString(), RegexOptions.IgnoreCase | RegexOptions.Compiled);
        }
    }
}
