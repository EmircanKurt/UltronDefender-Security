using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Configuration;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Reputation
{
    /// <summary>
    /// Abuse.ch MalwareBazaar API destekli, gerçek zamanlı bulut tehdit istihbaratı ve SHA-256 doğrulama servisi.
    /// - 1500ms sıkı zaman aşımı (tarama motorunun gecikmesini önler)
    /// - Bellek içi ConcurrentDictionary önbelleği (tekrarlayan sorguları önler)
    /// - SQLite ThreatSignatureDatabase ile otomatik öğrenme (öğrenilen zararlılar çevrimdışı taranabilir)
    /// - Kesintisiz ağ hata toleransı ve graceful degradation
    /// </summary>
    public class ReputationService : IReputationService, IDisposable
    {
        private const string MalwareBazaarApiEndpoint = "https://mb-api.abuse.ch/api/v1/";
        private const int MaxCacheEntries = 5000;
        private static readonly TimeSpan DefaultLookupTimeout = TimeSpan.FromMilliseconds(1500);
        private static readonly TimeSpan CleanCacheTtl = TimeSpan.FromHours(1);
        private static readonly TimeSpan MaliciousCacheTtl = TimeSpan.FromHours(24);

        private readonly ISettingsService? _settingsService;
        private readonly ILogger<ReputationService>? _logger;
        private readonly HttpClient _httpClient;
        private readonly bool _disposeClient;

        private bool _isCloudLookupEnabled;
        private readonly ConcurrentDictionary<string, (ReputationResult Result, DateTime CachedAt, bool IsMalicious)> _cache =
            new(StringComparer.OrdinalIgnoreCase);

        public bool IsCloudLookupEnabled
        {
            get => _isCloudLookupEnabled;
            set
            {
                _isCloudLookupEnabled = value;
                FeatureFlags.IsCloudLookupActive = value;
                if (_settingsService != null)
                {
                    _settingsService.SetSetting("IsCloudReputationEnabled", value);
                    _ = _settingsService.SaveAsync();
                }
            }
        }

        public int CacheCount => _cache.Count;

        public void ClearCache() => _cache.Clear();

        public ReputationService(
            ISettingsService? settingsService = null,
            ILogger<ReputationService>? logger = null,
            HttpClient? httpClient = null)
        {
            _settingsService = settingsService;
            _logger = logger;

            if (httpClient != null)
            {
                _httpClient = httpClient;
                _disposeClient = false;
            }
            else
            {
                _httpClient = new HttpClient();
                _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("UltronDefender-Security/2.0");
                _disposeClient = true;
            }

            _isCloudLookupEnabled = _settingsService?.GetSetting("IsCloudReputationEnabled", FeatureFlags.IsCloudLookupActive) 
                ?? FeatureFlags.IsCloudLookupActive;
        }

        public async Task<ReputationResult> CheckReputationAsync(string sha256, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sha256) || sha256.Length < 32)
            {
                return CreateOfflineResult("Geçersiz veya boş dosya hash'i.");
            }

            string normalizedHash = sha256.Trim().ToLowerInvariant();

            // Boş dosya (0-byte) SHA-256 özeti asla zararlı değildir
            if (normalizedHash.Equals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", StringComparison.OrdinalIgnoreCase))
            {
                return CreateOfflineResult("Boş dosya (0 byte).");
            }

            // 1. Bellek İçi Önbellek Kontrolü (O(1))
            if (_cache.TryGetValue(normalizedHash, out var cachedEntry))
            {
                var ttl = cachedEntry.IsMalicious ? MaliciousCacheTtl : CleanCacheTtl;
                if (DateTime.UtcNow - cachedEntry.CachedAt < ttl)
                {
                    return cachedEntry.Result;
                }
                _cache.TryRemove(normalizedHash, out _);
            }

            // 2. Yerel Genişletilmiş İmza Veritabanı Kontrolü
            var localMatch = ThreatSignatureDatabase.CheckHash(normalizedHash);
            if (localMatch.IsMatched)
            {
                var localResult = new ReputationResult
                {
                    IsKnown = true,
                    IsMalicious = true,
                    ThreatName = localMatch.Name,
                    Severity = localMatch.Severity > 0 ? localMatch.Severity : 100,
                    MalwareFamily = localMatch.Category,
                    Tags = string.IsNullOrEmpty(localMatch.Category) ? Array.Empty<string>() : new[] { localMatch.Category },
                    DetectionCount = 1,
                    TotalEngines = 1,
                    Source = "Yerel İstihbarat Veritabanı (Threat Intelligence Cache)",
                    CheckedAt = DateTime.UtcNow,
                    Details = $"Yerel SQLite veritabanı eşleşmesi: {localMatch.Name} ({localMatch.Category})"
                };

                EnforceCacheCapacity();
                _cache[normalizedHash] = (localResult, DateTime.UtcNow, true);
                return localResult;
            }

            // 3. Bulut Sorgusu Devre Dışı İse Çevrimdışı Güvenli Sonuç Dön
            if (!IsCloudLookupEnabled)
            {
                return CreateOfflineResult("Bulut tehdit sorgulaması devre dışı; yerel motor kullanıldı.");
            }

            // 4. Abuse.ch MalwareBazaar API Üzerinden Canlı Sorgulama (1500ms Timeout)
            try
            {
                using var timeoutCts = new CancellationTokenSource(DefaultLookupTimeout);
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                var formValues = new Dictionary<string, string>
                {
                    { "query", "get_info" },
                    { "hash", normalizedHash }
                };

                using var formContent = new FormUrlEncodedContent(formValues);
                using var response = await _httpClient.PostAsync(MalwareBazaarApiEndpoint, formContent, linkedCts.Token);

                if (response.IsSuccessStatusCode)
                {
                    var responseJson = await response.Content.ReadAsStringAsync(linkedCts.Token);
                    var cloudResult = ParseMalwareBazaarResponse(normalizedHash, responseJson);

                    EnforceCacheCapacity();
                    _cache[normalizedHash] = (cloudResult, DateTime.UtcNow, cloudResult.IsMalicious);

                    // Eğer bulut zararlı olduğunu onayladıysa, SQLite yerel veritabanına otomatik öğren
                    if (cloudResult.IsMalicious && !string.IsNullOrEmpty(cloudResult.ThreatName))
                    {
                        try
                        {
                            ThreatSignatureDatabase.ImportThreatHashes(new[]
                            {
                                (normalizedHash, cloudResult.ThreatName, cloudResult.MalwareFamily ?? "Cloud.MalwareBazaar", 100, "MalwareBazaar")
                            });
                            _logger?.LogInformation("Buluttan yeni tehdit imzası öğrenildi ve SQLite'a kaydedildi: {ThreatName} [{Hash}]", 
                                cloudResult.ThreatName, normalizedHash);
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogWarning(ex, "Buluttan öğrenilen imza SQLite'a kaydedilemedi: {Hash}", normalizedHash);
                        }
                    }

                    return cloudResult;
                }
                else
                {
                    _logger?.LogWarning("MalwareBazaar HTTP hatası döndürdü: {StatusCode}", response.StatusCode);
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // 1500ms zaman aşımı koruması tetiklendi
                _logger?.LogWarning("Bulut tehdit sorgulaması zaman aşımına uğradı (1500ms). Hash: {Hash}", normalizedHash);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Bulut tehdit sorgulaması sırasında ağ veya ayrıştırma hatası oluştu: {Hash}", normalizedHash);
            }

            // Ağ hatası veya zaman aşımı durumunda taramayı durdurmadan çevrimdışı temiz sonuç dön
            var fallbackResult = CreateOfflineResult("Bulut servisine ulaşılamadı; yerel doğrulama ile devam edildi.");
            _cache[normalizedHash] = (fallbackResult, DateTime.UtcNow, false);
            return fallbackResult;
        }

        private ReputationResult ParseMalwareBazaarResponse(string sha256, string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (root.TryGetProperty("query_status", out var statusElem))
                {
                    var status = statusElem.GetString();

                    if (string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase))
                    {
                        string threatName = "Generic.Malware";
                        string malwareFamily = "Malware";
                        var tags = new List<string>();

                        if (root.TryGetProperty("data", out var dataElem) &&
                            dataElem.ValueKind == JsonValueKind.Array &&
                            dataElem.GetArrayLength() > 0)
                        {
                            var first = dataElem[0];

                            if (first.TryGetProperty("signature", out var sigElem) &&
                                sigElem.ValueKind == JsonValueKind.String)
                            {
                                var sigStr = sigElem.GetString();
                                if (!string.IsNullOrWhiteSpace(sigStr))
                                {
                                    threatName = sigStr;
                                    malwareFamily = sigStr;
                                }
                            }

                            if (first.TryGetProperty("tags", out var tagsElem) &&
                                tagsElem.ValueKind == JsonValueKind.Array)
                            {
                                foreach (var tag in tagsElem.EnumerateArray())
                                {
                                    if (tag.ValueKind == JsonValueKind.String)
                                    {
                                        var t = tag.GetString();
                                        if (!string.IsNullOrWhiteSpace(t))
                                        {
                                            tags.Add(t);
                                        }
                                    }
                                }

                                if (threatName == "Generic.Malware" && tags.Count > 0)
                                {
                                    threatName = tags[0];
                                    malwareFamily = tags[0];
                                }
                            }
                        }

                        return new ReputationResult
                        {
                            IsKnown = true,
                            IsMalicious = true,
                            ThreatName = threatName,
                            Severity = 100,
                            MalwareFamily = malwareFamily,
                            Tags = tags.ToArray(),
                            DetectionCount = 1,
                            TotalEngines = 1,
                            Source = "Abuse.ch MalwareBazaar Cloud",
                            CheckedAt = DateTime.UtcNow,
                            Details = $"Bulut Tehdit İstihbaratı Eşleşmesi: {threatName}"
                        };
                    }
                    else if (string.Equals(status, "hash_not_found", StringComparison.OrdinalIgnoreCase))
                    {
                        return new ReputationResult
                        {
                            IsKnown = true,
                            IsMalicious = false,
                            DetectionCount = 0,
                            TotalEngines = 1,
                            Source = "Abuse.ch MalwareBazaar Cloud",
                            CheckedAt = DateTime.UtcNow,
                            Details = "MalwareBazaar veritabanında kayıt bulunamadı (Temiz / Bilinmeyen)."
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "MalwareBazaar JSON yanıtı ayrıştırılamadı.");
            }

            return CreateOfflineResult("MalwareBazaar yanıtı ayrıştırılamadı.");
        }

        private static ReputationResult CreateOfflineResult(string details)
        {
            return new ReputationResult
            {
                IsKnown = false,
                IsMalicious = false,
                DetectionCount = 0,
                TotalEngines = 0,
                Source = "Yerel Sezgisel Motor (Local Heuristics)",
                CheckedAt = DateTime.UtcNow,
                Details = details
            };
        }

        private void EnforceCacheCapacity()
        {
            if (_cache.Count > MaxCacheEntries)
            {
                var toRemove = _cache.Take(MaxCacheEntries / 5).Select(kv => kv.Key).ToList();
                foreach (var key in toRemove)
                {
                    _cache.TryRemove(key, out _);
                }
            }
        }

        public void Dispose()
        {
            if (_disposeClient)
            {
                _httpClient.Dispose();
            }
        }
    }
}
