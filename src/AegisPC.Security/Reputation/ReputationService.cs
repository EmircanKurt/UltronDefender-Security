using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
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
    /// Checks local threat signatures and, with explicit opt-in and an API key,
    /// queries MalwareBazaar for a SHA-256 hash. Missing evidence and cloud
    /// failures remain unknown; a confirmed cloud match may be learned locally.
    /// </summary>
    public class ReputationService : IReputationService, IDisposable
    {
        private const string MalwareBazaarApiEndpoint = "https://mb-api.abuse.ch/api/v1/";
        private const int MaxResponseBytes = 1024 * 1024;
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

        /// <summary>
        /// Gets or sets the opt-in cloud lookup preference. Changing the value
        /// persists it through the provided settings service when one exists.
        /// </summary>
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

        /// <summary>Gets the number of locally cached reputation responses.</summary>
        public int CacheCount => _cache.Count;

        /// <summary>Removes cached reputation responses without changing local signatures.</summary>
        public void ClearCache() => _cache.Clear();

        /// <summary>
        /// Creates a reputation service. An injected client remains owned by the
        /// caller; an internally created client is released on disposal.
        /// </summary>
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

        /// <summary>
        /// Checks a complete hexadecimal SHA-256 against local signatures and
        /// optionally MalwareBazaar. Invalid input, missing credentials, lookup
        /// failures, and absent catalogue entries return unknown; caller
        /// cancellation propagates.
        /// </summary>
        public async Task<ReputationResult> CheckReputationAsync(string sha256, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsValidSha256(sha256))
            {
                return CreateOfflineResult("Geçersiz veya boş dosya hash'i.");
            }

            string normalizedHash = sha256.ToLowerInvariant();

            // Boş dosya (0-byte) SHA-256 özeti asla zararlı değildir
            if (normalizedHash.Equals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", StringComparison.OrdinalIgnoreCase))
            {
                return CreateOfflineResult("Boş dosya (0 byte).");
            }

            // Newly learned local malicious evidence must override a cached
            // cloud catalogue miss immediately, without waiting for its TTL.
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

            if (_cache.TryGetValue(normalizedHash, out var cachedEntry))
            {
                var ttl = cachedEntry.IsMalicious ? MaliciousCacheTtl : CleanCacheTtl;
                if (DateTime.UtcNow - cachedEntry.CachedAt < ttl)
                    return cachedEntry.Result;

                _cache.TryRemove(normalizedHash, out _);
            }

            // Cloud lookup is opt-in; the local signature check above always runs.
            if (!IsCloudLookupEnabled)
            {
                return CreateOfflineResult("Bulut tehdit sorgulaması devre dışı; yerel motor kullanıldı.");
            }

            string? apiKey = _settingsService?.GetSetting("MalwareBazaarApiKey", string.Empty);
            if (apiKey is null || !IsValidApiKey(apiKey))
            {
                return CreateOfflineResult("MalwareBazaar API anahtarı eksik veya geçersiz; bulut sorgusu yapılmadı.");
            }

            return await QueryCloudAsync(normalizedHash, apiKey, cancellationToken);
        }

        private async Task<ReputationResult> QueryCloudAsync(
            string normalizedHash, string apiKey, CancellationToken cancellationToken)
        {
            try
            {
                using var timeoutCts = new CancellationTokenSource(DefaultLookupTimeout);
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
                using var request = new HttpRequestMessage(HttpMethod.Post, MalwareBazaarApiEndpoint);
                request.Headers.Add("Auth-Key", apiKey);
                request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "query", "get_info" },
                    { "hash", normalizedHash }
                });

                using var response = await _httpClient.SendAsync(
                    request, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token);
                if (!response.IsSuccessStatusCode)
                {
                    _logger?.LogWarning("MalwareBazaar returned HTTP {StatusCode}.", response.StatusCode);
                    return CreateOfflineResult("MalwareBazaar servisi kullanılamıyor; itibar bilinmiyor.");
                }

                var responseBytes = await ReadBoundedResponseAsync(response.Content, linkedCts.Token);
                if (responseBytes is null)
                {
                    _logger?.LogWarning("MalwareBazaar response exceeded the size limit.");
                    return CreateOfflineResult("MalwareBazaar yanıtı boyut sınırını aştı; itibar bilinmiyor.");
                }

                var cloudResult = ParseMalwareBazaarResponse(normalizedHash, responseBytes);

                // Unknown service errors are retried; only a confirmed match or
                // a valid catalogue miss is useful enough to cache.
                if (cloudResult.Source == "Abuse.ch MalwareBazaar Cloud")
                {
                    EnforceCacheCapacity();
                    _cache[normalizedHash] = (cloudResult, DateTime.UtcNow, cloudResult.IsMalicious);
                    if (cloudResult.IsMalicious && !string.IsNullOrEmpty(cloudResult.ThreatName))
                        LearnCloudThreat(normalizedHash, cloudResult);
                }

                return cloudResult;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                _logger?.LogWarning("MalwareBazaar lookup timed out.");
            }
            catch (Exception ex)
            {
                // Do not log exception details: an HTTP implementation may
                // include request headers and thus credentials in an exception.
                _logger?.LogWarning("MalwareBazaar lookup failed ({FailureType}).", ex.GetType().Name);
            }

            return CreateOfflineResult("Bulut servisine ulaşılamadı; itibar bilinmiyor.");
        }

        private static async Task<byte[]?> ReadBoundedResponseAsync(
            HttpContent content, CancellationToken cancellationToken)
        {
            if (content.Headers.ContentLength is > MaxResponseBytes)
                return null;

            await using var responseStream = await content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var readBuffer = new byte[8192];

            while (true)
            {
                // Read one byte beyond the limit to distinguish an exact-limit
                // response from a larger unknown-length response.
                int requested = Math.Min(readBuffer.Length, MaxResponseBytes + 1 - (int)buffer.Length);
                int read = await responseStream.ReadAsync(readBuffer.AsMemory(0, requested), cancellationToken);
                if (read == 0) return buffer.ToArray();
                if (buffer.Length + read > MaxResponseBytes) return null;
                buffer.Write(readBuffer, 0, read);
            }
        }

        private void LearnCloudThreat(string normalizedHash, ReputationResult cloudResult)
        {
            var threatName = cloudResult.ThreatName;
            if (string.IsNullOrEmpty(threatName)) return;

            try
            {
                var importedCount = ThreatSignatureDatabase.ImportThreatHashes(new[]
                {
                    (normalizedHash, threatName, cloudResult.MalwareFamily ?? "Cloud.MalwareBazaar", 100, "MalwareBazaar")
                });
                if (importedCount > 0)
                    _logger?.LogInformation("Learned MalwareBazaar threat signature for {Hash}.", normalizedHash);
                else
                    _logger?.LogWarning("MalwareBazaar signature was not stored for {Hash}.", normalizedHash);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning("MalwareBazaar signature could not be stored for {Hash} ({FailureType}).",
                    normalizedHash, ex.GetType().Name);
            }
        }

        private static bool IsValidSha256(string? sha256)
        {
            if (sha256 is null || sha256.Length != 64) return false;
            foreach (char ch in sha256)
            {
                if (!((ch >= '0' && ch <= '9') ||
                      (ch >= 'a' && ch <= 'f') ||
                      (ch >= 'A' && ch <= 'F')))
                    return false;
            }
            return true;
        }

        private static bool IsValidApiKey(string? apiKey)
        {
            if (string.IsNullOrEmpty(apiKey)) return false;
            foreach (char ch in apiKey)
            {
                if (ch <= ' ' || ch >= '\u007f') return false;
            }
            return true;
        }

        private ReputationResult ParseMalwareBazaarResponse(string sha256, ReadOnlyMemory<byte> json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object ||
                    !root.TryGetProperty("query_status", out var statusElem) ||
                    statusElem.ValueKind != JsonValueKind.String)
                {
                    return CreateOfflineResult("MalwareBazaar yanıtı geçersiz; itibar bilinmiyor.");
                }

                var status = statusElem.GetString();
                if (string.Equals(status, "hash_not_found", StringComparison.OrdinalIgnoreCase))
                    return new ReputationResult
                    {
                        IsKnown = false,
                        IsMalicious = false,
                        DetectionCount = 0,
                        TotalEngines = 0,
                        Source = "Abuse.ch MalwareBazaar Cloud",
                        CheckedAt = DateTime.UtcNow,
                        Details = "MalwareBazaar veritabanında kayıt bulunamadı; itibar bilinmiyor."
                    };

                if (string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase) &&
                    root.TryGetProperty("data", out var dataElem) &&
                    dataElem.ValueKind == JsonValueKind.Array &&
                    dataElem.GetArrayLength() > 0 &&
                    dataElem[0].ValueKind == JsonValueKind.Object &&
                    dataElem[0].TryGetProperty("sha256_hash", out var hashElem) &&
                    hashElem.ValueKind == JsonValueKind.String &&
                    string.Equals(hashElem.GetString(), sha256, StringComparison.OrdinalIgnoreCase))
                {
                    return ParseMatchedThreat(dataElem[0]);
                }
            }
            catch (JsonException ex)
            {
                _logger?.LogWarning("MalwareBazaar returned invalid JSON ({FailureType}).", ex.GetType().Name);
            }

            return CreateOfflineResult("MalwareBazaar yanıtı geçersiz veya sorgu başarısız; itibar bilinmiyor.");
        }

        private static ReputationResult ParseMatchedThreat(JsonElement first)
        {
            string threatName = "Generic.Malware";
            string malwareFamily = "Malware";
            var tags = new List<string>();

            if (first.TryGetProperty("signature", out var sigElem) &&
                sigElem.ValueKind == JsonValueKind.String &&
                sigElem.GetString() is { Length: > 0 } signature &&
                !string.IsNullOrWhiteSpace(signature))
            {
                threatName = signature;
                malwareFamily = threatName;
            }

            if (first.TryGetProperty("tags", out var tagsElem) &&
                tagsElem.ValueKind == JsonValueKind.Array)
            {
                foreach (var tag in tagsElem.EnumerateArray())
                {
                    if (tag.ValueKind == JsonValueKind.String &&
                        tag.GetString() is { Length: > 0 } text &&
                        !string.IsNullOrWhiteSpace(text))
                        tags.Add(text);
                }

                if (threatName == "Generic.Malware" && tags.Count > 0)
                {
                    threatName = tags[0];
                    malwareFamily = threatName;
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

        /// <summary>Disposes the internally created HTTP client, if any.</summary>
        public void Dispose()
        {
            if (_disposeClient)
            {
                _httpClient.Dispose();
            }
        }
    }
}
