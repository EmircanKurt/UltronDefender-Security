using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Trait("Category", "LiveSample")]
    public class LiveSampleTests : IDisposable
    {
        private readonly string _tempWorkingDir;
        private readonly HttpClient _httpClient;
        public const string EicarPayload = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

        public LiveSampleTests()
        {
            _tempWorkingDir = Path.Combine(Path.GetTempPath(), $"AegisPC_LiveSample_{Guid.NewGuid():N}");
            Directory.CreateDirectory(_tempWorkingDir);
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempWorkingDir))
                {
                    Directory.Delete(_tempWorkingDir, recursive: true);
                }
            }
            catch
            {
                // Test cleanup
            }
            _httpClient.Dispose();
        }

        [Fact]
        public async Task Test_Eicar_EndToEnd_DetectedBy_Hash_Yara_And_EtwPreExec()
        {
            // %TEMP% altında geçici EICAR test ikilisi oluştur
            string tempEicarFile = Path.Combine(_tempWorkingDir, $"live_eicar_{Guid.NewGuid():N}.com");
            await File.WriteAllBytesAsync(tempEicarFile, Encoding.ASCII.GetBytes(EicarPayload));

            try
            {
                // Katman 1: Hash ve İmza Veritabanı (Hash Lookup Layer)
                var hashService = new HashService();
                string computedHash = await hashService.ComputeSha256Async(tempEicarFile);
                Assert.Equal(EicarSha256, computedHash);

                var hashResult = MalwareSignatureDatabase.CheckHash(computedHash);
                Assert.True(hashResult.IsMatched, "EICAR hash katmanında mutlaka tespit edilmelidir.");
                Assert.Equal(100, hashResult.SeverityScore);
                Assert.Equal("TestMalware", hashResult.ThreatCategory);

                // Katman 2: YARA Motoru ve Dedektörü (YARA Pattern & Offset Layer)
                var yaraEngine = new YaraEngine();
                var yaraMatches = await yaraEngine.ScanFileAsync(tempEicarFile);
                Assert.NotEmpty(yaraMatches);

                var eicarRuleMatch = yaraMatches.FirstOrDefault(m => m.RuleName.Contains("EICAR", StringComparison.OrdinalIgnoreCase));
                Assert.NotNull(eicarRuleMatch);
                Assert.Equal(100, eicarRuleMatch.Severity);
                Assert.NotEmpty(eicarRuleMatch.MatchedStrings);
                Assert.Equal(0, eicarRuleMatch.MatchedStrings.First().Offset);

                var yaraDetector = new YaraDetector(yaraEngine);
                var yaraEvidences = (await yaraDetector.EvaluateAsync(new DetectionContext { FilePath = tempEicarFile })).ToList();
                Assert.NotEmpty(yaraEvidences);
                Assert.Equal(EvidenceConfidence.Absolute, yaraEvidences.First().Confidence);
                Assert.Equal(100, yaraEvidences.First().ScoreContribution);

                // Katman 3: ETW Tabanlı Pre-Exec Tarama ve Engelleme Katmanı (Pre-Exec Gating Layer)
                var sigVerifier = new SignatureVerifier();
                var riskScorer = new RiskScoringEngine();
                var detectionHub = DetectionHubFactory.CreateDefault(
                    hashService: hashService,
                    signatureVerifier: sigVerifier,
                    yaraEngine: yaraEngine);

                PreExecThreatAlert? blockedAlert = null;
                var etwPreExec = new EtwPreExecProtectionService(detectionHub, riskScorer, sigVerifier)
                {
                    ScanTimeout = TimeSpan.FromSeconds(3)
                };
                etwPreExec.OnThreatBlocked += alert => blockedAlert = alert;

                var decision = await etwPreExec.EvaluateProcessAsync(65432, tempEicarFile);

                Assert.True(decision.WasBlocked, "EICAR, ETW pre-exec katmanında çalıştırılmadan engellenmelidir.");
                Assert.True(decision.RiskScore >= 70, $"Risk skoru >= 70 olmalıdır (Gerçek: {decision.RiskScore}).");
                Assert.NotNull(blockedAlert);
                Assert.Equal(65432, blockedAlert.ProcessId);
                Assert.Equal(tempEicarFile, blockedAlert.ImagePath);
            }
            finally
            {
                // ASLA repoya dosya commit edilmez - %TEMP% temizliği zorunludur
                if (File.Exists(tempEicarFile))
                {
                    File.Delete(tempEicarFile);
                }
            }
        }

        [Fact]
        public async Task Test_LiveSample_CleanFile_PermitsAcrossAllLayers()
        {
            string cleanFile = Path.Combine(_tempWorkingDir, "clean_sample.exe");
            await File.WriteAllTextAsync(cleanFile, "Clean harmless application binary content without malicious indicators.");

            try
            {
                var hashService = new HashService();
                var sigVerifier = new SignatureVerifier();
                var riskScorer = new RiskScoringEngine();
                var yaraEngine = new YaraEngine();
                var detectionHub = DetectionHubFactory.CreateDefault(
                    hashService: hashService,
                    signatureVerifier: sigVerifier,
                    yaraEngine: yaraEngine);

                var etwPreExec = new EtwPreExecProtectionService(detectionHub, riskScorer, sigVerifier);
                var decision = await etwPreExec.EvaluateProcessAsync(54321, cleanFile);

                Assert.False(decision.WasBlocked);
                Assert.True(decision.RiskScore < 70);
                Assert.Equal("Clean execution permitted", decision.Reason);
            }
            finally
            {
                if (File.Exists(cleanFile))
                {
                    File.Delete(cleanFile);
                }
            }
        }

        [Fact]
        public async Task Test_MalwareBazaar_QueryRecentSamples_WithStrict30sTimeout()
        {
            string sampleOutputPath = Path.Combine(_tempWorkingDir, "bazaar_query_output.json");

            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

                // MalwareBazaar API get_recent sorgusu
                var requestContent = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("query", "get_recent"),
                    new KeyValuePair<string, string>("selector", "time")
                });

                using var request = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/")
                {
                    Content = requestContent
                };
                request.Headers.Add("User-Agent", "UltronDefender-ThreatFeed");

                HttpResponseMessage response;
                try
                {
                    response = await _httpClient.SendAsync(request, cts.Token);
                }
                catch (Exception netEx) when (netEx is HttpRequestException or TaskCanceledException or OperationCanceledException)
                {
                    // Ağ / ISP erişim engeli veya timeout durumunda test güvenle tamamlanır
                    return;
                }

                if (response.IsSuccessStatusCode)
                {
                    var jsonBytes = await response.Content.ReadAsByteArrayAsync(cts.Token);
                    await File.WriteAllBytesAsync(sampleOutputPath, jsonBytes, cts.Token);

                    Assert.True(File.Exists(sampleOutputPath));
                    long fileSize = new FileInfo(sampleOutputPath).Length;
                    Assert.True(fileSize > 0, "İndirilen veri 0 bayttan büyük olmalıdır.");

                    using var doc = JsonDocument.Parse(jsonBytes);
                    if (doc.RootElement.TryGetProperty("query_status", out var statusProp))
                    {
                        string status = statusProp.GetString() ?? string.Empty;
                        Assert.Contains(status.ToLowerInvariant(), new[] { "ok", "success", "illegal_query", "no_results" });
                    }
                }
            }
            finally
            {
                if (File.Exists(sampleOutputPath))
                {
                    File.Delete(sampleOutputPath);
                }
            }
        }
    }
}
