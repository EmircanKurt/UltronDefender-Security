using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Network
{
    public enum UrlBlockCategory
    {
        Phishing,
        Malvertising,
        C2Server,
        CryptoMining,
        Custom
    }

    public record UrlBlockRule
    {
        public string RawRule { get; init; } = string.Empty;
        public string Pattern { get; init; } = string.Empty;
        public UrlBlockCategory Category { get; init; }
        public bool IsRegex { get; init; }
        public Regex? CompiledRegex { get; init; }
        public string Source { get; init; } = "Local";
    }

    public record UrlEvaluationResult
    {
        public bool IsBlocked { get; init; }
        public string MatchedPattern { get; init; } = string.Empty;
        public UrlBlockCategory? Category { get; init; }
        public string Reason { get; init; } = string.Empty;
        public int RiskScore { get; init; } = 0;
    }

    /// <summary>
    /// Çevrimdışı URL ve alan adı kara liste yöneticisi.
    /// .txt dosyalarından (Hosts, AdBlock ve Regex formatları) kuralları yükler,
    /// alt alan adlarını (subdomains) ve tam URL yollarını yüksek başarımda denetler.
    /// </summary>
    public class UrlBlocklistManager
    {
        private readonly ILogger<UrlBlocklistManager>? _logger;
        private readonly ConcurrentDictionary<string, (UrlBlockCategory Category, string Source)> _exactDomains = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<UrlBlockRule> _regexRules = new();
        private readonly object _regexLock = new();
        private readonly string _blocklistDirectory;

        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(50);

        public int TotalDomainRules => _exactDomains.Count;
        public int TotalRegexRules
        {
            get
            {
                lock (_regexLock) return _regexRules.Count;
            }
        }

        public string BlocklistDirectory => _blocklistDirectory;

        public UrlBlocklistManager(string? blocklistDirectory = null, ILogger<UrlBlocklistManager>? logger = null)
        {
            _logger = logger;

            if (!string.IsNullOrWhiteSpace(blocklistDirectory))
            {
                _blocklistDirectory = blocklistDirectory;
            }
            else
            {
                string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _blocklistDirectory = Path.Combine(programData, "UltronDefender", "Blocklists");
            }

            // 1. Gömülü çevrimdışı varsayılan kuralları yükle
            LoadEmbeddedDefaultSignatures();

            // 2. Varsa diskteki dizinden yükle
            LoadFromDirectory(_blocklistDirectory);
        }

        /// <summary>
        /// Belirtilen dizindeki tüm .txt kural dosyalarını tarar ve kuralları içeri aktarır.
        /// Dosya adı ipucuna göre kategori atar (phishing.txt, c2_abusech.txt vb.)
        /// </summary>
        public void LoadFromDirectory(string directoryPath)
        {
            try
            {
                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                    CreateDefaultTemplateFiles(directoryPath);
                    return;
                }

                var files = Directory.GetFiles(directoryPath, "*.txt");
                foreach (var file in files)
                {
                    string fileName = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    UrlBlockCategory category = fileName switch
                    {
                        var n when n.Contains("phish") => UrlBlockCategory.Phishing,
                        var n when n.Contains("malvertis") || n.Contains("ad") => UrlBlockCategory.Malvertising,
                        var n when n.Contains("c2") || n.Contains("abuse") || n.Contains("threatfox") || n.Contains("urlhaus") => UrlBlockCategory.C2Server,
                        var n when n.Contains("crypto") || n.Contains("coin") || n.Contains("miner") => UrlBlockCategory.CryptoMining,
                        _ => UrlBlockCategory.Custom
                    };

                    LoadFile(file, category);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Kural dizini taranırken hata oluştu: {Dir}", directoryPath);
            }
        }

        /// <summary>
        /// Tekil bir .txt kural dosyasını satır satır okuyup ayrıştırır.
        /// </summary>
        public void LoadFile(string filePath, UrlBlockCategory category)
        {
            if (!File.Exists(filePath)) return;

            try
            {
                var lines = File.ReadAllLines(filePath);
                string source = Path.GetFileName(filePath);

                foreach (var line in lines)
                {
                    AddRule(line, category, source);
                }

                _logger?.LogInformation("{File} dosyasından kurallar yüklendi (Toplam Domain: {Count}).", source, _exactDomains.Count);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Kural dosyası okunurken hata oluştu: {Path}", filePath);
            }
        }

        /// <summary>
        /// Ham kural metnini ayrıştırıp uygun veri yapısına ekler.
        /// Formatlar:
        /// 1. Hosts formatı: '127.0.0.1 evil.com' veya '0.0.0.0 evil.com'
        /// 2. AdBlock formatı: '||badsite.com^'
        /// 3. Regex formatı: 'regex:^https?:\/\/.*\/gate\.php\?id='
        /// 4. Düz alan adı: 'evil-c2.net'
        /// </summary>
        public void AddRule(string rawLine, UrlBlockCategory category, string source = "Manual")
        {
            if (string.IsNullOrWhiteSpace(rawLine)) return;

            string line = rawLine.Trim();

            // Yorum satırlarını atla (#, !, //)
            if (line.StartsWith("#") || line.StartsWith("!") || line.StartsWith("//"))
            {
                return;
            }

            // 1. Regex kuralı
            if (line.StartsWith("regex:", StringComparison.OrdinalIgnoreCase))
            {
                string pattern = line.Substring("regex:".Length).Trim();
                try
                {
                    var regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);
                    lock (_regexLock)
                    {
                        _regexRules.Add(new UrlBlockRule
                        {
                            RawRule = line,
                            Pattern = pattern,
                            Category = category,
                            IsRegex = true,
                            CompiledRegex = regex,
                            Source = source
                        });
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Geçersiz Regex kuralı: {Pattern}", pattern);
                }
                return;
            }

            // 2. Hosts formatı: '0.0.0.0 evil.com' veya '127.0.0.1 evil.com'
            if (line.StartsWith("0.0.0.0 ") || line.StartsWith("127.0.0.1 ") || line.StartsWith("0.0.0.0\t") || line.StartsWith("127.0.0.1\t"))
            {
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    line = parts[1];
                }
            }

            // 3. AdBlock sözdizimi: '||evil.com^'
            if (line.StartsWith("||") && line.EndsWith("^"))
            {
                line = line.Substring(2, line.Length - 3);
            }
            else if (line.StartsWith("||"))
            {
                line = line.Substring(2);
            }

            // Temizleme ve alan adı doğrulama
            string cleanDomain = CleanDomain(line);
            if (!string.IsNullOrEmpty(cleanDomain) && cleanDomain.Contains('.'))
            {
                _exactDomains[cleanDomain] = (category, source);
            }
        }

        /// <summary>
        /// Bir URL veya alan adını kara liste kurallarına göre inceler.
        /// </summary>
        public UrlEvaluationResult EvaluateUrl(string urlOrDomain)
        {
            if (string.IsNullOrWhiteSpace(urlOrDomain))
            {
                return new UrlEvaluationResult { IsBlocked = false };
            }

            string host = ExtractHost(urlOrDomain);
            string fullUrl = urlOrDomain.Trim();

            // 1. Tam alan adı ve alt alan adı (subdomain) hiyerarşisi kontrolü
            if (!string.IsNullOrEmpty(host))
            {
                string current = host;
                while (!string.IsNullOrEmpty(current))
                {
                    if (_exactDomains.TryGetValue(current, out var match))
                    {
                        return new UrlEvaluationResult
                        {
                            IsBlocked = true,
                            Category = match.Category,
                            MatchedPattern = current,
                            Reason = $"Alan adı kara listede mevcut ({match.Category}): {current} (Kaynak: {match.Source})",
                            RiskScore = match.Category switch
                            {
                                UrlBlockCategory.C2Server => 100,
                                UrlBlockCategory.Phishing => 95,
                                UrlBlockCategory.CryptoMining => 85,
                                UrlBlockCategory.Malvertising => 70,
                                _ => 80
                            }
                        };
                    }

                    // Bir üst alan adına geç: 'api.badsite.com' -> 'badsite.com'
                    int dotIndex = current.IndexOf('.');
                    if (dotIndex > 0 && dotIndex < current.Length - 1)
                    {
                        current = current.Substring(dotIndex + 1);
                    }
                    else
                    {
                        break;
                    }
                }
            }

            // 2. Regex Kuralları Kontrolü
            lock (_regexLock)
            {
                foreach (var rule in _regexRules)
                {
                    if (rule.CompiledRegex != null)
                    {
                        try
                        {
                            if (rule.CompiledRegex.IsMatch(fullUrl) || rule.CompiledRegex.IsMatch(host))
                            {
                                return new UrlEvaluationResult
                                {
                                    IsBlocked = true,
                                    Category = rule.Category,
                                    MatchedPattern = rule.Pattern,
                                    Reason = $"URL Regex kuralı ile eşleşti ({rule.Category}): {rule.Pattern}",
                                    RiskScore = 90
                                };
                            }
                        }
                        catch (RegexMatchTimeoutException) { }
                    }
                }
            }

            return new UrlEvaluationResult { IsBlocked = false, RiskScore = 0 };
        }

        /// <summary>
        /// Yalnızca alan adı bazında hızlı sorgu yapar.
        /// </summary>
        public bool IsDomainBlocked(string domain, out UrlBlockCategory category, out string matchedDomain)
        {
            var res = EvaluateUrl(domain);
            if (res.IsBlocked && res.Category.HasValue)
            {
                category = res.Category.Value;
                matchedDomain = res.MatchedPattern;
                return true;
            }

            category = UrlBlockCategory.Custom;
            matchedDomain = string.Empty;
            return false;
        }

        /// <summary>
        /// Hosts dosyasına aktarmak üzere tüm aktif engelli alan adlarını kategori bilgisiyle listeler.
        /// </summary>
        public IReadOnlyList<(string Domain, string Category)> GetEntriesForHostsInjection()
        {
            return _exactDomains
                .Select(kv => (Domain: kv.Key, Category: kv.Value.Category.ToString()))
                .OrderBy(kv => kv.Category)
                .ThenBy(kv => kv.Domain)
                .ToList();
        }

        public IReadOnlyList<string> GetAllBlockedDomains(UrlBlockCategory? filterCategory = null)
        {
            return _exactDomains
                .Where(kv => !filterCategory.HasValue || kv.Value.Category == filterCategory.Value)
                .Select(kv => kv.Key)
                .OrderBy(d => d)
                .ToList();
        }

        private void LoadEmbeddedDefaultSignatures()
        {
            // 1. PHISHING (Kimlik Avı)
            string[] phishingDefaults = {
                "paypa1-security-check.com",
                "micros0ft-support-alert.xyz",
                "steamcommunity-trade-bot.xyz",
                "update-windows-defender-security.top",
                "appleid-verify-alert.com",
                "binance-security-login.net",
                "netflix-account-recovery-portal.com",
                "chase-online-verification.xyz",
                "discord-free-nitro-claim.info",
                "login-microsoftonline-portal.top"
            };
            foreach (var d in phishingDefaults) _exactDomains[d] = (UrlBlockCategory.Phishing, "Embedded-Phishing");

            // 2. C2 SERVERS (Komuta Kontrol / abuse.ch Feodo & ThreatFox & URLhaus)
            string[] c2Defaults = {
                "c2-redline-stealer.biz",
                "cobaltstrike-listener.xyz",
                "icedid-loader-gate.net",
                "qakbot-c2-node.top",
                "lokibot-command.org",
                "feodo-tracker-gate.cc",
                "asyncrat-dns-server.top",
                "remcos-c2-listener.cloud",
                "lumma-stealer-drop.com",
                "emotet-epoch-dist.net"
            };
            foreach (var d in c2Defaults) _exactDomains[d] = (UrlBlockCategory.C2Server, "Embedded-abuse.ch");

            // 3. CRYPTO MINING (İzinsiz Tarayıcı ve Arka Plan Madenciliği)
            string[] cryptoDefaults = {
                "coinhive.com",
                "cryptoloot.pro",
                "coin-have.com",
                "monerominer.rocks",
                "webminepool.com",
                "jsecoin.com",
                "xmrig-proxy.online",
                "minr.pw",
                "authedmine.com",
                "coinimp.com"
            };
            foreach (var d in cryptoDefaults) _exactDomains[d] = (UrlBlockCategory.CryptoMining, "Embedded-NoCoin");

            // 4. MALVERTISING (Zararlı Reklam & İzleyici Ağları)
            string[] malvertisingDefaults = {
                "malvertising-traffic-hub.top",
                "popunder-network.xyz",
                "telemetry-tracker-ad.biz",
                "click-fraud-redirector.info",
                "fake-virus-alert-system.top",
                "ad-delivery-network.online"
            };
            foreach (var d in malvertisingDefaults) _exactDomains[d] = (UrlBlockCategory.Malvertising, "Embedded-Malvertising");
        }

        private static void CreateDefaultTemplateFiles(string directoryPath)
        {
            try
            {
                File.WriteAllText(Path.Combine(directoryPath, "phishing.txt"),
                    "# AegisPC Phishing Blocklist\r\npaypa1-security-check.com\r\nmicros0ft-support-alert.xyz\r\n");

                File.WriteAllText(Path.Combine(directoryPath, "c2_abusech.txt"),
                    "# AegisPC C2 Servers (abuse.ch feed)\r\nc2-redline-stealer.biz\r\ncobaltstrike-listener.xyz\r\nicedid-loader-gate.net\r\n");

                File.WriteAllText(Path.Combine(directoryPath, "cryptomining.txt"),
                    "# AegisPC Cryptomining Blocklist\r\ncoinhive.com\r\ncryptoloot.pro\r\n");

                File.WriteAllText(Path.Combine(directoryPath, "malvertising.txt"),
                    "# AegisPC Malvertising Blocklist\r\nmalvertising-traffic-hub.top\r\npopunder-network.xyz\r\n");
            }
            catch { }
        }

        private static string CleanDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return string.Empty;
            string clean = domain.Trim().ToLowerInvariant();

            if (clean.StartsWith("http://") || clean.StartsWith("https://"))
            {
                if (Uri.TryCreate(clean, UriKind.Absolute, out var uri))
                {
                    clean = uri.Host;
                }
            }

            clean = clean.Split('/')[0].Split(':')[0].Trim();
            return clean.TrimStart('.');
        }

        private static string ExtractHost(string urlOrDomain)
        {
            if (string.IsNullOrWhiteSpace(urlOrDomain)) return string.Empty;
            string clean = urlOrDomain.Trim();

            if (!clean.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !clean.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                clean = "https://" + clean;
            }

            if (Uri.TryCreate(clean, UriKind.Absolute, out var uri))
            {
                return uri.Host.ToLowerInvariant();
            }

            return CleanDomain(urlOrDomain);
        }
    }
}
