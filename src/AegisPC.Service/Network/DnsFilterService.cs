using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Network
{
    public record DnsResolutionResult
    {
        public string Domain { get; init; } = string.Empty;
        public bool IsBlocked { get; init; }
        public UrlBlockCategory? BlockCategory { get; init; }
        public string Reason { get; init; } = string.Empty;
        public IPAddress[] ResolvedAddresses { get; init; } = Array.Empty<IPAddress>();
        public string ResolutionSource { get; init; } = "Unknown";
        public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
    }

    public record DnsFilterStatistics
    {
        public int TotalDomainRules { get; init; }
        public int TotalRegexRules { get; init; }
        public long TotalQueriesEvaluated { get; init; }
        public long BlockedQueriesCount { get; init; }
        public long AllowedQueriesCount { get; init; }
        public bool IsHostsSinkholeActive { get; init; }
        public int HostsSinkholeEntriesCount { get; init; }
    }

    /// <summary>
    /// Çevrimdışı ve Yerel DNS Filtreleme Servisi (DnsFilterService).
    /// Hosts dosyası enjeksiyonu, yerel kural motoru ve Cloudflare (1.1.1.1) DNS over HTTPS (DoH)
    /// çözümleyicisini koordine eder. Çevrimdışı modda sıfır sızıntı ile yerel sinkhole sağlar.
    /// </summary>
    public class DnsFilterService : IDisposable
    {
        private readonly ILogger<DnsFilterService>? _logger;
        private readonly UrlBlocklistManager _blocklistManager;
        private readonly HostsInjectionHelper _hostsHelper;
        private readonly HttpClient _httpClient;
        private readonly bool _ownsHttpClient;

        // Yerel DNS Çözümleme Önbelleği (Offline DNS Cache)
        private readonly ConcurrentDictionary<string, (IPAddress[] IPs, DateTime ExpiryUtc)> _dnsCache = new(StringComparer.OrdinalIgnoreCase);

        private long _totalQueries;
        private long _blockedQueries;
        private long _allowedQueries;

        public const string CloudflareDohUrl = "https://1.1.1.1/dns-query";

        public UrlBlocklistManager BlocklistManager => _blocklistManager;
        public HostsInjectionHelper HostsHelper => _hostsHelper;

        public DnsFilterService(
            UrlBlocklistManager? blocklistManager = null,
            HostsInjectionHelper? hostsHelper = null,
            HttpClient? httpClient = null,
            ILogger<DnsFilterService>? logger = null)
        {
            _logger = logger;
            _blocklistManager = blocklistManager ?? new UrlBlocklistManager();
            _hostsHelper = hostsHelper ?? new HostsInjectionHelper();

            if (httpClient != null)
            {
                _httpClient = httpClient;
                _ownsHttpClient = false;
            }
            else
            {
                _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                _ownsHttpClient = true;
            }
        }

        /// <summary>
        /// Alan adının kara listede olup olmadığını yerel kurallarla değerlendirir.
        /// </summary>
        public bool IsDomainBlocked(string domain, out UrlBlockCategory category, out string reason)
        {
            Interlocked.Increment(ref _totalQueries);

            var res = _blocklistManager.EvaluateUrl(domain);
            if (res.IsBlocked && res.Category.HasValue)
            {
                Interlocked.Increment(ref _blockedQueries);
                category = res.Category.Value;
                reason = res.Reason;
                return true;
            }

            Interlocked.Increment(ref _allowedQueries);
            category = UrlBlockCategory.Custom;
            reason = string.Empty;
            return false;
        }

        /// <summary>
        /// Alan adını çözümler; engelli ise anında 127.0.0.1 / 0.0.0.0 sinkhole adresine yönlendirir.
        /// İzinli ise yerel önbellekten veya Cloudflare DoH (1.1.1.1) üzerinden IP adresini döndürür.
        /// </summary>
        public async Task<DnsResolutionResult> ResolveDomainAsync(
            string domain,
            bool useDohIfOnline = true,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                return new DnsResolutionResult
                {
                    Domain = string.Empty,
                    IsBlocked = false,
                    ResolutionSource = "None"
                };
            }

            string cleanDomain = domain.Trim().ToLowerInvariant().TrimEnd('.');

            // 1. Yerel Kara Liste Denetimi (Offline Sinkhole Kararı)
            if (IsDomainBlocked(cleanDomain, out var category, out var reason))
            {
                _logger?.LogWarning("🛡️ DNS Filtresi: '{Domain}' erişimi engellendi! Kategori: {Cat}", cleanDomain, category);
                return new DnsResolutionResult
                {
                    Domain = cleanDomain,
                    IsBlocked = true,
                    BlockCategory = category,
                    Reason = reason,
                    ResolvedAddresses = new[] { IPAddress.Parse("127.0.0.1"), IPAddress.Parse("0.0.0.0") },
                    ResolutionSource = "Local-Sinkhole"
                };
            }

            // 2. Yerel Önbellek Kontrolü (Cache Hit)
            if (_dnsCache.TryGetValue(cleanDomain, out var cached) && DateTime.UtcNow < cached.ExpiryUtc)
            {
                return new DnsResolutionResult
                {
                    Domain = cleanDomain,
                    IsBlocked = false,
                    ResolvedAddresses = cached.IPs,
                    ResolutionSource = "Local-Cache"
                };
            }

            // 3. DNS over HTTPS (Cloudflare 1.1.1.1) veya Sistem Fallback
            IPAddress[] resolvedIps = Array.Empty<IPAddress>();
            string source = "Offline-Fallback";

            if (useDohIfOnline)
            {
                try
                {
                    resolvedIps = await QueryCloudflareDohAsync(cleanDomain, cancellationToken);
                    if (resolvedIps.Length > 0)
                    {
                        source = "Cloudflare-DoH";
                        // 1 saatlik önbellekleme
                        _dnsCache[cleanDomain] = (resolvedIps, DateTime.UtcNow.AddHours(1));
                    }
                }
                catch
                {
                    // Çevrimdışı ortam: DoH erişilemezse standart DNS'e düş veya yerel döngü
                }
            }

            // 4. Standart DNS Çözümleme Fallback
            if (resolvedIps.Length == 0)
            {
                try
                {
                    resolvedIps = await Dns.GetHostAddressesAsync(cleanDomain, cancellationToken);
                    if (resolvedIps.Length > 0)
                    {
                        source = "System-DNS";
                        _dnsCache[cleanDomain] = (resolvedIps, DateTime.UtcNow.AddMinutes(30));
                    }
                }
                catch
                {
                    // Ağ yok veya çözülemedi
                    resolvedIps = Array.Empty<IPAddress>();
                    source = "Resolution-Failed";
                }
            }

            return new DnsResolutionResult
            {
                Domain = cleanDomain,
                IsBlocked = false,
                ResolvedAddresses = resolvedIps,
                ResolutionSource = source
            };
        }

        /// <summary>
        /// Mevcut tüm kara liste kurallarını Windows hosts dosyasına enjekte eder.
        /// </summary>
        public bool SyncWithHostsFile(SinkholeIpMode ipMode = SinkholeIpMode.Loopback)
        {
            var entries = _blocklistManager.GetEntriesForHostsInjection();
            bool success = _hostsHelper.ApplySinkhole(entries, ipMode);
            if (success)
            {
                _logger?.LogInformation("DnsFilterService: Hosts dosyası başarıyla senkronize edildi ({Count} kayıt).", entries.Count);
            }
            return success;
        }

        /// <summary>
        /// Hosts dosyasındaki sinkhole bloğunu kaldırır.
        /// </summary>
        public bool RemoveFromHostsFile()
        {
            return _hostsHelper.RemoveSinkhole();
        }

        /// <summary>
        /// Kural dosyalarını yeniden yükler ve önbelleği temizler.
        /// </summary>
        public void ReloadRules()
        {
            _dnsCache.Clear();
            _blocklistManager.LoadFromDirectory(_blocklistManager.BlocklistDirectory);
            _logger?.LogInformation("DnsFilterService: Kurallar yeniden yüklendi.");
        }

        /// <summary>
        /// Filtreleme motorunun anlık çalışma istatistiklerini döndürür.
        /// </summary>
        public DnsFilterStatistics GetStatistics()
        {
            return new DnsFilterStatistics
            {
                TotalDomainRules = _blocklistManager.TotalDomainRules,
                TotalRegexRules = _blocklistManager.TotalRegexRules,
                TotalQueriesEvaluated = _totalQueries,
                BlockedQueriesCount = _blockedQueries,
                AllowedQueriesCount = _allowedQueries,
                IsHostsSinkholeActive = _hostsHelper.IsSinkholeActive(),
                HostsSinkholeEntriesCount = _hostsHelper.GetSinkholeEntryCount()
            };
        }

        /// <summary>
        /// Cloudflare DoH (1.1.1.1) API üzerinden JSON formatında DNS A ve AAAA kayıtlarını sorgular.
        /// </summary>
        private async Task<IPAddress[]> QueryCloudflareDohAsync(string domain, CancellationToken ct)
        {
            var list = new List<IPAddress>();
            try
            {
                string queryUrl = $"{CloudflareDohUrl}?name={Uri.EscapeDataString(domain)}&type=A";
                using var req = new HttpRequestMessage(HttpMethod.Get, queryUrl);
                req.Headers.Add("Accept", "application/dns-json");

                using var resp = await _httpClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                if (resp.IsSuccessStatusCode)
                {
                    using var stream = await resp.Content.ReadAsStreamAsync(ct);
                    using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

                    if (doc.RootElement.TryGetProperty("Answer", out var answerProp) && answerProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in answerProp.EnumerateArray())
                        {
                            if (item.TryGetProperty("data", out var dataProp))
                            {
                                string? ipStr = dataProp.GetString();
                                if (!string.IsNullOrEmpty(ipStr) && IPAddress.TryParse(ipStr, out var ip))
                                {
                                    list.Add(ip);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Cloudflare DoH sorgusu başarısız oldu: {Domain}", domain);
            }

            return list.ToArray();
        }

        public void Dispose()
        {
            if (_ownsHttpClient)
            {
                _httpClient.Dispose();
            }
        }
    }
}
