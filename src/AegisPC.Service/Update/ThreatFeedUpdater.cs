using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Update
{
    /// <summary>
    /// Açık kaynak tehdit istihbaratı beslemelerini (abuse.ch MalwareBazaar, URLhaus, vb.)
    /// periyodik olarak indiren ve yerel SQLite tehdit veritabanını güncelleyen servis.
    /// </summary>
    public class ThreatFeedUpdater
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<ThreatFeedUpdater>? _logger;
        private static readonly string MalwareBazaarRecentUrl = "https://bazaar.abuse.ch/export/csv/recent/";

        public ThreatFeedUpdater(HttpClient? httpClient = null, ILogger<ThreatFeedUpdater>? logger = null)
        {
            _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            _logger = logger;
        }

        /// <summary>
        /// MalwareBazaar son tehdit beslemesini indirip yerel imza veritabanına aktarır.
        /// </summary>
        public async Task<int> UpdateFromMalwareBazaarAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger?.LogInformation("MalwareBazaar tehdit beslemesi indiriliyor: {Url}", MalwareBazaarRecentUrl);

                using var request = new HttpRequestMessage(HttpMethod.Get, MalwareBazaarRecentUrl);
                request.Headers.Add("User-Agent", "UltronDefender-ThreatIntel/1.0");

                using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    _logger?.LogWarning("MalwareBazaar beslemesi indirilemedi. HTTP {StatusCode}", response.StatusCode);
                    return 0;
                }

                using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                using var reader = new StreamReader(stream);

                var threats = new List<(string Sha256, string Name, string Category, int Severity, string Source)>();
                string? line;

                while ((line = await reader.ReadLineAsync(cancellationToken)) != null)
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;

                    // MalwareBazaar CSV Format:
                    // # "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
                    var cols = ParseCsvLine(line);
                    if (cols.Count >= 9)
                    {
                        string sha256 = cols[1].Trim('"', ' ');
                        string fileName = cols.Count > 5 ? cols[5].Trim('"', ' ') : string.Empty;
                        string signature = cols.Count > 8 ? cols[8].Trim('"', ' ') : string.Empty;
                        string fileType = cols.Count > 6 ? cols[6].Trim('"', ' ') : "exe";

                        if (sha256.Length == 64)
                        {
                            string threatName = !string.IsNullOrEmpty(signature) && signature != "n/a"
                                ? $"Malware.{signature}"
                                : (!string.IsNullOrEmpty(fileName) ? $"Malware.Generic.{fileName}" : "Malware.MalwareBazaar.Dropper");

                            string category = DetectCategory(fileType, signature);

                            threats.Add((sha256, threatName, category, 100, "MalwareBazaar.abuse.ch"));
                        }
                    }
                }

                if (threats.Count > 0)
                {
                    int imported = ThreatSignatureDatabase.ImportThreatHashes(threats);
                    _logger?.LogInformation("MalwareBazaar'dan {Count} adet yeni zararlı yazılım imzası içeri aktarıldı.", imported);
                    return imported;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Tehdit beslemesi güncellenirken hata oluştu.");
            }

            return 0;
        }

        private static string DetectCategory(string fileType, string signature)
        {
            string sigLower = signature.ToLowerInvariant();
            if (sigLower.Contains("ransom") || sigLower.Contains("lockbit") || sigLower.Contains("wannacry") || sigLower.Contains("stop"))
                return "Ransomware";
            if (sigLower.Contains("stealer") || sigLower.Contains("redline") || sigLower.Contains("raccoon") || sigLower.Contains("vidar") || sigLower.Contains("lumma"))
                return "Infostealer";
            if (sigLower.Contains("rat") || sigLower.Contains("remcos") || sigLower.Contains("asyncrat") || sigLower.Contains("quasar"))
                return "Backdoor/RAT";
            if (sigLower.Contains("loader") || sigLower.Contains("emotet") || sigLower.Contains("qakbot") || sigLower.Contains("icedid"))
                return "Dropper/Loader";
            if (sigLower.Contains("miner") || sigLower.Contains("xmrig"))
                return "Cryptominer";

            return "Malware";
        }

        private static List<string> ParseCsvLine(string line)
        {
            var result = new List<string>();
            bool inQuotes = false;
            int start = 0;

            for (int i = 0; i < line.Length; i++)
            {
                if (line[i] == '"')
                {
                    inQuotes = !inQuotes;
                }
                else if (line[i] == ',' && !inQuotes)
                {
                    result.Add(line.Substring(start, i - start));
                    start = i + 1;
                }
            }

            if (start <= line.Length)
            {
                result.Add(line.Substring(start));
            }

            return result;
        }
    }
}
