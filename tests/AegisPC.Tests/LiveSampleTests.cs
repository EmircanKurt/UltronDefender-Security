using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Kernel;
using AegisPC.Contracts.Policy;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Behavior;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Security.Kernel;
using AegisPC.Security.Policy;
using AegisPC.Security.RealTime;
using AegisPC.Security.Safety;
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

        [Fact]
        public async Task Test_LiveValidation_Eicar_FullChainVerification_AcrossAllEngines()
        {
            string tempEicar = Path.Combine(_tempWorkingDir, $"fullchain_eicar_{Guid.NewGuid():N}.com");
            await File.WriteAllTextAsync(tempEicar, EicarPayload);

            try
            {
                // 1. Hash Database
                var hashService = new HashService();
                string hash = await hashService.ComputeSha256Async(tempEicar);
                var hashMatch = MalwareSignatureDatabase.CheckHash(hash);
                Assert.True(hashMatch.IsMatched);
                Assert.Equal(100, hashMatch.SeverityScore);

                // 2. YARA Engine
                var yaraEngine = new YaraEngine();
                var yaraMatches = await yaraEngine.ScanFileAsync(tempEicar);
                Assert.Contains(yaraMatches, m => m.RuleName.Contains("EICAR", StringComparison.OrdinalIgnoreCase));

                // 3. AMSI Engine
                using var amsiService = new AmsiScanService();
                var amsiResult = await amsiService.ScanStringAsync(EicarPayload, "eicar.com");
                Assert.True(amsiResult.IsMalicious);

                // 4. Kernel Gating Engine
                var kernelEngine = new KernelGatingEngine();
                var kernelDecision = await kernelEngine.EvaluatePreOpDecisionAsync(new KernelIpcMessage
                {
                    MessageId = 9001,
                    OpCode = MinifilterOperationType.PreCreate,
                    ProcessId = 7777,
                    FilePath = tempEicar,
                    TimeoutMs = 500
                });
                Assert.True(kernelDecision.IsBlocked);
                Assert.Equal(0xC0000022u, kernelDecision.NtStatus);
                Assert.True(kernelDecision.ShouldQuarantine);
                Assert.True(kernelDecision.RiskScore >= 85);
            }
            finally
            {
                if (File.Exists(tempEicar)) File.Delete(tempEicar);
            }
        }

        [Fact]
        public async Task Test_LiveValidation_BatchScriptDropper_BlockedAcrossEngines()
        {
            string dropperScript = "@echo off\r\nvssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled No\r\npowershell -w hidden -enc JABhID0A...";
            string tempDropper = Path.Combine(_tempWorkingDir, "vssadmin_drop.bat");
            await File.WriteAllTextAsync(tempDropper, dropperScript);

            try
            {
                // 1. AMSI Script Scanner
                using var amsi = new AmsiScanService();
                var amsiRes = await amsi.ScanStringAsync(dropperScript, "vssadmin_drop.bat");
                Assert.True(amsiRes.IsMalicious);

                // 2. Kernel Gating Pre-Op
                var kernelGating = new KernelGatingEngine();
                var gatingDecision = await kernelGating.EvaluatePreOpDecisionAsync(new KernelIpcMessage
                {
                    MessageId = 9002,
                    OpCode = MinifilterOperationType.PreCreate,
                    ProcessId = 8888,
                    FilePath = tempDropper,
                    TimeoutMs = 500
                });

                Assert.True(gatingDecision.IsBlocked);
                Assert.Equal(0xC0000022u, gatingDecision.NtStatus);
                Assert.True(gatingDecision.RiskScore >= 85);
            }
            finally
            {
                if (File.Exists(tempDropper)) File.Delete(tempDropper);
            }
        }

        [Fact]
        public void Test_LiveValidation_ProcessHollowing_DetectedByBehaviorEngine()
        {
            var detector = new ProcessInjectionDetector();
            var hollowingApis = new[]
            {
                "ZwUnmapViewOfSection",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "SetThreadContext"
            };

            var eval = detector.EvaluateApiSequence(1234, 5678, hollowingApis, "malware_loader.exe", "svchost.exe");

            Assert.True(eval.IsInjectionDetected);
            Assert.Equal(ProcessInjectionTechnique.ProcessHollowing, eval.Technique);
            Assert.True(eval.SeverityScore >= 90);
            Assert.Contains("Process Hollowing", eval.Explanation, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task Test_LiveValidation_BenignCommercialInstaller_PermittedWithoutFalsePositive()
        {
            string installerPath = Path.Combine(_tempWorkingDir, "GoogleChromeStandaloneEnterprise64.exe");
            await File.WriteAllTextAsync(installerPath, "MZ-simulated-benign-google-installer-payload");

            try
            {
                var fakeVerifier = new LiveSampleFakeSignatureVerifier("Google LLC", isValid: true);
                var kernelGating = new KernelGatingEngine(signatureVerifier: fakeVerifier);

                var decision = await kernelGating.EvaluatePreOpDecisionAsync(new KernelIpcMessage
                {
                    MessageId = 9003,
                    OpCode = MinifilterOperationType.PreCreate,
                    ProcessId = 9999,
                    FilePath = installerPath,
                    TimeoutMs = 500
                });

                Assert.False(decision.IsBlocked);
                Assert.Equal(0x00000000u, decision.NtStatus);
                Assert.Equal(KernelGatingStatus.BypassedTrustedProcess, decision.Status);
                Assert.False(decision.ShouldQuarantine);
                Assert.Equal(0, decision.RiskScore);
            }
            finally
            {
                if (File.Exists(installerPath)) File.Delete(installerPath);
            }
        }

        [Fact]
        public async Task Test_Live_RealEicarDrop_PolicyEngine_AutoQuarantine_VaultAndUndoLog()
        {
            string vaultDir = Path.Combine(_tempWorkingDir, "QuarantineVault");
            string undoDir = Path.Combine(_tempWorkingDir, "UndoStorage");
            Directory.CreateDirectory(vaultDir);
            Directory.CreateDirectory(undoDir);

            string liveEicarFile = Path.Combine(_tempWorkingDir, $"live_drop_{Guid.NewGuid():N}.com");
            await File.WriteAllTextAsync(liveEicarFile, EicarPayload);
            Assert.True(File.Exists(liveEicarFile), "Canlı EICAR test dosyası diske başarıyla yazılmalıdır.");

            try
            {
                var hashService = new HashService();
                var sigVerifier = new SignatureVerifier();
                var findingService = new SecurityFindingService();
                var quarantineService = new QuarantineService(hashService, customVaultDir: vaultDir);
                var undoLogService = new QuarantineUndoLogService(quarantineService, customStoragePath: undoDir);

                var policyEngine = new PolicyEngine(
                    quarantineService: quarantineService,
                    findingService: findingService,
                    signatureVerifier: sigVerifier,
                    undoLogService: undoLogService);

                var finding = new SecurityFinding
                {
                    Id = Guid.NewGuid(),
                    ObjectName = Path.GetFileName(liveEicarFile),
                    ObjectPath = liveEicarFile,
                    RiskScore = 100,
                    RiskLevel = RiskLevel.ConfirmedMalicious,
                    Category = FindingCategory.KnownMalwareHash,
                    Title = "EICAR-Standard-AV-Test-File"
                };

                // 1. Politika Motorunu İnfaz Et (Policy Enforcement)
                var result = await policyEngine.EnforcePolicyAsync(finding);

                // 2. Doğrulamalar: Karar Otomatik Karantina olmalı ve başarıyla sonuçlanmalı
                Assert.Equal(PolicyDecisionAction.AutoQuarantine, result.Action);
                Assert.True(result.QuarantinedSuccessfully, "PolicyEngine karantina infazı başarılı dönmelidir.");

                // 3. Dosya Orijinal Konumundan Silinmiş/Taşınmış Olmalıdır
                Assert.False(File.Exists(liveEicarFile), "Karantinaya alınan dosya orijinal disk yolundan kaldırılmış olmalıdır.");

                // 4. Karantina Kasasında AES-256 Şifreli Olarak Mevcut Olmalıdır
                var quarantinedList = await quarantineService.GetQuarantinedItemsAsync();
                Assert.Single(quarantinedList);
                var entry = quarantinedList[0];
                Assert.Equal(Path.GetFileName(liveEicarFile), entry.FileName);
                Assert.True(File.Exists(entry.QuarantinePath), "Karantina kasasındaki şifreli dosya diskte var olmalıdır.");
                Assert.True(new FileInfo(entry.QuarantinePath).Length > 0, "Kasaya alınan dosya boyutu 0'dan büyük olmalıdır.");

                // 5. 30 Günlük Geri Alma Günlüğünde (Undo Log) Kayıt Bulunmalıdır
                var undoEntries = await undoLogService.GetUndoLogEntriesAsync();
                Assert.Single(undoEntries);
                var undoEntry = undoEntries[0];
                Assert.Equal(100, undoEntry.RiskScore);
                Assert.Equal(liveEicarFile, undoEntry.OriginalPath);
                Assert.Contains("Otomatik Karantina", undoEntry.DecisionChain);
                Assert.False(undoEntry.IsRestored);

                // 6. Güvenli Geri Yükleme (Undo / Restore) Doğrulaması
                int restoredCount = await undoLogService.BulkRestoreAsync(new[] { undoEntry.QuarantineId });
                Assert.Equal(1, restoredCount);
                Assert.True(File.Exists(liveEicarFile), "Geri yüklenen dosya orijinal konumunda yeniden var olmalıdır.");
                string restoredPayload = await File.ReadAllTextAsync(liveEicarFile);
                Assert.Equal(EicarPayload, restoredPayload);
                Assert.True(undoEntry.IsRestored, "Geri alınan kaydın durumu IsRestored=true olmalıdır.");
            }
            finally
            {
                if (File.Exists(liveEicarFile))
                {
                    try { File.Delete(liveEicarFile); } catch { }
                }
            }
        }

        [Fact]
        public async Task Test_Live_RealProcess_PreExecSuspension_And_ExplorerSafetyCheck()
        {
            // 1. Gerçek Bir Windows Süreci Başlat (cmd.exe /c ping ...)
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c ping 127.0.0.1 -n 15 > nul",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var dummyProc = Process.Start(psi);
            Assert.NotNull(dummyProc);
            Assert.False(dummyProc.HasExited, "Canlı test süreci başlatılmış ve çalışıyor olmalıdır.");
            int livePid = dummyProc.Id;

            string fakeMalwareFile = Path.Combine(_tempWorkingDir, $"live_threat_{Guid.NewGuid():N}.exe");
            await File.WriteAllTextAsync(fakeMalwareFile, EicarPayload);

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

                var etwPreExec = new EtwPreExecProtectionService(detectionHub, riskScorer, sigVerifier)
                {
                    ScanTimeout = TimeSpan.FromSeconds(5)
                };

                // 2. Canlı Süreç Değerlendirmesi: NtSuspendProcess + DetectionHub + KillProcessTree
                var decision = await etwPreExec.EvaluateProcessAsync(livePid, fakeMalwareFile);

                // 3. Askıya Alma ve Engelleme Doğrulaması
                Assert.True(decision.WasSuspended, "Canlı süreç NtSuspendProcess ile başarıyla dondurulmalıdır.");
                Assert.True(decision.WasBlocked, "Zararlı süreç engellenmelidir.");
                Assert.True(decision.RiskScore >= 70, $"Risk skoru >= 70 olmalıdır (Gerçek: {decision.RiskScore}).");

                // 4. Sürecin Sonlandırıldığını Doğrula (KillProcessTree)
                dummyProc.WaitForExit(4000);
                Assert.True(dummyProc.HasExited, "Zararlı süreç derhal öldürülmüş olmalıdır (HasExited == true).");

                // 5. Kritik Sistem Süreci (explorer.exe) Whitelist ve Güvenlik Doğrulaması
                var explorerProc = Process.GetProcessesByName("explorer").FirstOrDefault();
                if (explorerProc != null)
                {
                    string explorerPath = explorerProc.MainModule?.FileName ?? @"C:\Windows\explorer.exe";
                    var explorerDecision = await etwPreExec.EvaluateProcessAsync(explorerProc.Id, explorerPath);

                    Assert.True(explorerDecision.Whitelisted, "explorer.exe kritik sistem süreci olarak hızlıca allowlist'e alınmalıdır.");
                    Assert.False(explorerDecision.WasSuspended, "explorer.exe ASLA askıya alınmamalı veya rehin tutulmamalıdır (WasSuspended == false).");
                    Assert.False(explorerDecision.WasBlocked, "explorer.exe ASLA engellenmemelidir (WasBlocked == false).");
                    Assert.False(explorerProc.HasExited, "explorer.exe kesintisiz çalışmaya devam etmelidir.");
                }

                // 6. Kritik Süreç İsimleri Listesi (CriticalProcesses.List) Kontrolleri
                string[] criticalNames = { "csrss.exe", "dwm.exe", "lsass.exe", "svchost.exe", "services.exe", "wininit.exe" };
                foreach (var critName in criticalNames)
                {
                    string sysPath = Path.Combine(Environment.SystemDirectory, critName);
                    var critDecision = await etwPreExec.EvaluateProcessAsync(99999, sysPath);
                    Assert.True(critDecision.Whitelisted, $"{critName} kesinlikle kritik süreç listesinde olmalıdır.");
                    Assert.False(critDecision.WasSuspended, $"{critName} asla askıya alınmamalıdır.");
                    Assert.False(critDecision.WasBlocked, $"{critName} asla engellenmemelidir.");
                }
            }
            finally
            {
                if (!dummyProc.HasExited)
                {
                    try { dummyProc.Kill(true); } catch { }
                }
                if (File.Exists(fakeMalwareFile))
                {
                    try { File.Delete(fakeMalwareFile); } catch { }
                }
            }
        }

        [Fact]
        public async Task Test_Live_RealTimeWatcher_FileSystemWatcher_EicarDrop_AutoQuarantine()
        {
            string watchDir = Path.Combine(_tempWorkingDir, "RtWatchFolder");
            string vaultDir = Path.Combine(_tempWorkingDir, "RtVault");
            Directory.CreateDirectory(watchDir);
            Directory.CreateDirectory(vaultDir);

            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskScorer = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var fileScanner = new FileScannerService(hashService, sigVerifier, riskScorer, allowlist, findingService);
            var quarantineService = new QuarantineService(hashService, customVaultDir: vaultDir);

            var rtEngine = new RealTimeProtectionEngine(
                fileScanner,
                hashService,
                sigVerifier,
                riskScorer,
                quarantineService,
                findingService);

            try
            {
                // İzleyiciyi sadece özel test klasörümüzde başlat (default locations devre dışı)
                rtEngine.Start(watchDefaultLocations: false);
                rtEngine.AddWatchDirectory(watchDir);

                // Real-time izleme altında klasöre EICAR bırak
                string liveDropFile = Path.Combine(watchDir, "rt_drop_eicar.com");
                await File.WriteAllTextAsync(liveDropFile, EicarPayload);
                Assert.True(File.Exists(liveDropFile));

                // FileSystemWatcher + Worker havuzunun tespit ve karantina infazını bekle
                bool quarantined = false;
                for (int i = 0; i < 60; i++)
                {
                    await Task.Delay(100);
                    if (!File.Exists(liveDropFile))
                    {
                        quarantined = true;
                        break;
                    }
                }

                Assert.True(quarantined, "Real-time FileSystemWatcher, bırakılan EICAR dosyasını algılayıp otomatik karantinaya taşımalıdır.");

                // Kasada dosyanın bulunduğunu doğrula
                var quarantinedList = await quarantineService.GetQuarantinedItemsAsync();
                Assert.NotEmpty(quarantinedList);
                Assert.Equal("rt_drop_eicar.com", quarantinedList[0].FileName);
                Assert.True(File.Exists(quarantinedList[0].QuarantinePath));
            }
            finally
            {
                rtEngine.Stop();
            }
        }

        private class LiveSampleFakeSignatureVerifier : ISignatureVerifier
        {
            private readonly string _publisher;
            private readonly bool _isValid;

            public LiveSampleFakeSignatureVerifier(string publisher, bool isValid = true)
            {
                _publisher = publisher;
                _isValid = isValid;
            }

            public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default)
            {
                return Task.FromResult(new SignatureInfo
                {
                    IsSigned = true,
                    IsValid = _isValid,
                    Publisher = _publisher
                });
            }
        }
    }
}
