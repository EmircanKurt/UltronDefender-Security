using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Update
{
    /// <summary>
    /// Açık kaynak tehdit istihbaratı beslemelerini (abuse.ch MalwareBazaar JSON API)
    /// periyodik olarak indiren ve yerel SQLite tehdit veritabanını güncelleyen servis.
    /// </summary>
    public class ThreatFeedUpdater
    {
        private readonly HttpClient _httpClient;
        private readonly ISettingsService? _settingsService;
        private readonly ILogger<ThreatFeedUpdater>? _logger;
        private readonly IYaraEngine? _yaraEngine;
        public const string MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/";

        public ThreatFeedUpdater(
            HttpClient? httpClient = null,
            ISettingsService? settingsService = null,
            ILogger<ThreatFeedUpdater>? logger = null,
            IYaraEngine? yaraEngine = null)
        {
            _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            _settingsService = settingsService;
            _logger = logger;
            _yaraEngine = yaraEngine;
        }

        /// <summary>
        /// YARA kural dizinindeki kuralları yeniden yükler ve derler.
        /// </summary>
        public void ReloadYaraRules()
        {
            try
            {
                _yaraEngine?.ReloadRules();
                _logger?.LogInformation("YARA kuralları başarıyla yeniden derlendi.");
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "YARA kuralları yeniden derlenirken hata oluştu.");
            }
        }

        /// <summary>
        /// MalwareBazaar tehdit beslemesini JSON API üzerinden indirip yerel imza veritabanına aktarır.
        /// İlk açılışta bootstrap modunda çalışır (get_recent limit=1000 + tag=exe,rat,ransomware,stealer),
        /// sonraki çağrılarda 24 saat dolmadan tekrar sorgulama yapmayarak delta çeker.
        /// </summary>
        public async Task<int> UpdateFromMalwareBazaarAsync(
            bool force = false,
            bool? forceBootstrap = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. API anahtarını SettingsService'ten oku (asla kod içine gömülmez)
                string? apiKey = _settingsService?.GetSetting<string>("MalwareBazaarApiKey", string.Empty);
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    _logger?.LogWarning("MalwareBazaar güncellemesi atlandı: auth-key tanımlı değil");
                    return 0;
                }

                // 2. 24 Saatlik Zaman Aşımı / Rate-Limit Kontrolü
                DateTime? lastUpdate = _settingsService?.GetSetting<DateTime?>("LastThreatFeedUpdateUtc", null);
                if (!force && lastUpdate.HasValue && (DateTime.UtcNow - lastUpdate.Value) < TimeSpan.FromHours(24))
                {
                    _logger?.LogInformation("MalwareBazaar güncellemesi atlandı: 24 saatlik süre dolmadı (Son: {LastUpdate:u}).", lastUpdate.Value);
                    return 0;
                }

                bool isBootstrap = forceBootstrap ?? !lastUpdate.HasValue;
                _logger?.LogInformation("MalwareBazaar tehdit beslemesi başlatılıyor (Mod: {Mode}, Url: {Url})",
                    isBootstrap ? "BOOTSTRAP" : "DELTA", MalwareBazaarApiUrl);

                var queryBatch = new List<Dictionary<string, string>>();

                if (isBootstrap)
                {
                    // 1. İlk açılış: son eklenen 1000 tehdit
                    queryBatch.Add(new Dictionary<string, string>
                    {
                        { "query", "get_recent" },
                        { "selector", "time" },
                        { "limit", "1000" }
                    });

                    // 2. Windows ile ilgili kritik tag bazlı geçmiş imzalar (her biri limit=100)
                    string[] tags = { "exe", "rat", "ransomware", "stealer" };
                    foreach (var tag in tags)
                    {
                        queryBatch.Add(new Dictionary<string, string>
                        {
                            { "query", "get_taginfo" },
                            { "tag", tag },
                            { "limit", "100" }
                        });
                    }
                }
                else
                {
                    // Delta güncelleme: Yalnızca en son eklenenler
                    queryBatch.Add(new Dictionary<string, string>
                    {
                        { "query", "get_recent" },
                        { "selector", "time" }
                    });
                }

                var allThreats = new List<(string Sha256, string Name, string Category, int Severity, string Source)>();

                for (int i = 0; i < queryBatch.Count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var formData = queryBatch[i];

                    var threats = await FetchThreatsAsync(formData, apiKey, cancellationToken);
                    if (threats.Count > 0)
                    {
                        allThreats.AddRange(threats);
                    }

                    // API rate-limit nezaketi: çoklu sorgular arasında kısa bekleme
                    if (isBootstrap && i < queryBatch.Count - 1)
                    {
                        try
                        {
                            await Task.Delay(250, cancellationToken);
                        }
                        catch (OperationCanceledException)
                        {
                            break;
                        }
                    }
                }

                if (allThreats.Count > 0)
                {
                    // Yinelenen hash'leri ayıkla
                    var distinctThreats = allThreats
                        .GroupBy(t => t.Sha256, StringComparer.OrdinalIgnoreCase)
                        .Select(g => g.First())
                        .ToList();

                    int imported = ThreatSignatureDatabase.ImportThreatHashes(distinctThreats);
                    _logger?.LogInformation("MalwareBazaar'dan {Count} adet yeni zararlı yazılım imzası içeri aktarıldı ({Mode}).",
                        imported, isBootstrap ? "Bootstrap" : "Delta");

                    // YARA kural havuzunu yeniden derle
                    ReloadYaraRules();

                    // Başarılı indirme zaman damgasını ayarlara yaz
                    try
                    {
                        _settingsService?.SetSetting("LastThreatFeedUpdateUtc", DateTime.UtcNow);
                        if (_settingsService != null)
                        {
                            await _settingsService.SaveAsync(cancellationToken);
                        }
                    }
                    catch (Exception saveEx)
                    {
                        _logger?.LogWarning(saveEx, "Son tehdit beslemesi zaman damgası ayarlara kaydedilemedi.");
                    }

                    return imported;
                }
            }
            catch (OperationCanceledException)
            {
                _logger?.LogWarning("MalwareBazaar tehdit beslemesi indirme işlemi iptal edildi veya zaman aşımına uğradı.");
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Tehdit beslemesi güncellenirken hata oluştu.");
            }

            return 0;
        }

        private async Task<List<(string Sha256, string Name, string Category, int Severity, string Source)>> FetchThreatsAsync(
            Dictionary<string, string> formData,
            string apiKey,
            CancellationToken cancellationToken)
        {
            var results = new List<(string Sha256, string Name, string Category, int Severity, string Source)>();

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, MalwareBazaarApiUrl);
                request.Headers.Add("Auth-Key", apiKey);
                request.Headers.Add("User-Agent", "UltronDefender-ThreatFeed");
                request.Content = new FormUrlEncodedContent(formData);

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(30));

                using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                if (!response.IsSuccessStatusCode)
                {
                    _logger?.LogWarning("MalwareBazaar API başarısız HTTP durum kodu döndürdü: {StatusCode}", response.StatusCode);
                    return results;
                }

                using var stream = await response.Content.ReadAsStreamAsync(cts.Token);
                using var jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cts.Token);
                var root = jsonDoc.RootElement;

                if (!root.TryGetProperty("query_status", out var statusProp))
                {
                    _logger?.LogWarning("MalwareBazaar API query_status alanı bulunamadı.");
                    return results;
                }

                string status = statusProp.GetString() ?? string.Empty;
                if (!string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(status, "success", StringComparison.OrdinalIgnoreCase))
                {
                    _logger?.LogWarning("MalwareBazaar API başarısız durum döndürdü: {Status}", status);
                    return results;
                }

                if (!root.TryGetProperty("data", out var dataProp) || dataProp.ValueKind != JsonValueKind.Array)
                {
                    return results;
                }

                foreach (var item in dataProp.EnumerateArray())
                {
                    if (!item.TryGetProperty("sha256_hash", out var shaProp)) continue;
                    string? sha256 = shaProp.GetString();
                    if (string.IsNullOrWhiteSpace(sha256) || sha256.Length != 64) continue;

                    string signature = item.TryGetProperty("signature", out var sigProp) ? (sigProp.GetString() ?? string.Empty) : string.Empty;
                    string fileType = item.TryGetProperty("file_type", out var ftProp) ? (ftProp.GetString() ?? "exe") : "exe";

                    string threatName = !string.IsNullOrEmpty(signature) && !string.Equals(signature, "n/a", StringComparison.OrdinalIgnoreCase)
                        ? $"Malware.{signature}"
                        : "Malware.Generic.MalwareBazaar";

                    string category = DetectCategory(fileType, signature);

                    results.Add((sha256.Trim().ToLowerInvariant(), threatName, category, 100, "MalwareBazaar"));
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "MalwareBazaar sorgusu başarısız oldu: {Query}",
                    formData.TryGetValue("query", out var q) ? q : "unknown");
            }

            return results;
        }

        public static string DetectCategory(string fileType, string signature)
        {
            string ftLower = (fileType ?? string.Empty).Trim().ToLowerInvariant();
            // Linux ve macOS örneklerini "Linux/Mac" olarak etiketle (Windows taramasında varsayılan aramada öne çıkmasınlar)
            if (ftLower is "elf" or "sh" or "macos" or "macho" or "dylib" or "so" or "bash" or "zsh")
            {
                return "Linux/Mac";
            }

            string sigLower = (signature ?? string.Empty).ToLowerInvariant();
            if (sigLower.Contains("ransom") || sigLower.Contains("lockbit") || sigLower.Contains("wannacry") || sigLower.Contains("stop"))
                return "Ransomware";
            if (sigLower.Contains("stealer") || sigLower.Contains("redline") || sigLower.Contains("raccoon") || sigLower.Contains("vidar") || sigLower.Contains("lumma"))
                return "Infostealer";
            if (sigLower.Contains("rat") || sigLower.Contains("remcos") || sigLower.Contains("asyncrat") || sigLower.Contains("quasar") || sigLower.Contains("mirai") || sigLower.Contains("botnet"))
                return "Backdoor/RAT";
            if (sigLower.Contains("loader") || sigLower.Contains("emotet") || sigLower.Contains("qakbot") || sigLower.Contains("icedid"))
                return "Dropper/Loader";
            if (sigLower.Contains("miner") || sigLower.Contains("xmrig"))
                return "Cryptominer";

            return "Malware";
        }
    }
}
