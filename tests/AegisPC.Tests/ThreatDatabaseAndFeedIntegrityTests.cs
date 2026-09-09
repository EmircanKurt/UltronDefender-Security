using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Infrastructure;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.Scanning;
using AegisPC.Service.Update;
using Xunit;

namespace AegisPC.Tests
{
    public class ThreatDatabaseAndFeedIntegrityTests
    {
        [Fact]
        public void Test_ThreatSignatureDatabase_EmbeddedDataset_ContainsOnlyVerifiedEicarHashes()
        {
            // Görev 1: Gömülü imzalarda sahte/desensel hash'lerin temizlendiğini doğrula
            ThreatSignatureDatabase.ResetForTesting();
            ThreatSignatureDatabase.Initialize();

            // 1. Doğrulanmış EICAR hash'leri mutlaka mevcut olmalıdır
            var eicar1 = ThreatSignatureDatabase.CheckHash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
            var eicar2 = ThreatSignatureDatabase.CheckHash("131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbcf18291");

            Assert.True(eicar1.IsMatched, "EICAR standard hash must match.");
            Assert.Equal("EICAR-Standard-AV-Test-File", eicar1.Name);
            Assert.True(eicar2.IsMatched, "EICAR CRLF hash must match.");
            Assert.Equal("EICAR-Standard-AV-Test-CRLF", eicar2.Name);

            // 2. Doğrulanamayan / sahte / sentetik hash'ler silinmiş olmalıdır
            var fake1 = ThreatSignatureDatabase.CheckHash("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00");
            var fake2 = ThreatSignatureDatabase.CheckHash("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
            var fake3 = ThreatSignatureDatabase.CheckHash("5a8b7c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b");
            var fake4 = ThreatSignatureDatabase.CheckHash("4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e");

            Assert.False(fake1.IsMatched, "Synthetic CobaltStrike hash must be purged.");
            Assert.False(fake2.IsMatched, "Synthetic Beacon hash must be purged.");
            Assert.False(fake3.IsMatched, "Synthetic njRAT hash must be purged.");
            Assert.False(fake4.IsMatched, "Synthetic Emotet hash must be purged.");
        }

        [Fact]
        public void Test_ThreatSignatureDatabase_DetectsTampering_AndRecreatesDatabase()
        {
            // Görev 3: SQLite veritabanı dosyasının SHA-256 bütünlük kontrolü ve kurcalama (tampering) tespiti
            string testDir = Path.Combine(Path.GetTempPath(), "AegisTest_DbIntegrity_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testDir);
            string dbPath = Path.Combine(testDir, "threat_signatures.db");
            string hashPath = dbPath + ".sha256";

            try
            {
                // 1. İlk ilklendirme — dosya ve checksum oluşmalı
                ThreatSignatureDatabase.ResetForTesting(dbPath);
                Assert.True(File.Exists(dbPath), "SQLite veritabanı dosyası oluşturulmalıdır.");
                Assert.True(File.Exists(hashPath), "SHA-256 checksum dosyası oluşturulmalıdır.");

                string initialHash = File.ReadAllText(hashPath).Trim();
                Assert.Equal(64, initialHash.Length);

                // 2. Veritabanını kurcala (tamper) — havuzları temizle ve dosyanın sonuna bozuk veri ekle
                Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                File.AppendAllText(dbPath, "-- TAMPERED BY ATTACKER --");
                string tamperedFileHash = ThreatSignatureDatabase.ComputeFileSha256(dbPath);
                Assert.NotEqual(initialHash, tamperedFileHash);

                // 3. Veritabanını yeniden yükle — kurcalama tespit edilmeli, dosya sıfırlanıp yeniden oluşturulmalı
                ThreatSignatureDatabase.ResetForTesting(dbPath);

                Assert.True(File.Exists(dbPath), "Veritabanı sıfırlanıp yeniden oluşturulmalıdır.");
                Assert.True(File.Exists(hashPath), "Checksum güncellenmelidir.");

                string refreshedHash = File.ReadAllText(hashPath).Trim();
                string actualNewHash = ThreatSignatureDatabase.ComputeFileSha256(dbPath);
                Assert.Equal(refreshedHash, actualNewHash);

                // EICAR sağlam olmalıdır
                var eicar = ThreatSignatureDatabase.CheckHash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
                Assert.True(eicar.IsMatched);
            }
            finally
            {
                // Temizlik
                ThreatSignatureDatabase.ResetForTesting();
                try
                {
                    if (Directory.Exists(testDir))
                    {
                        Directory.Delete(testDir, true);
                    }
                }
                catch { }
            }
        }

        [Fact]
        public void Test_ThreatSignatureDatabase_TryTightenFileAcl_ExecutesSafely()
        {
            // Görev 3: ACL sıkılaştırma metodunun Windows üzerinde güvenle çalıştığını doğrula
            string tempFile = Path.GetTempFileName();
            try
            {
                bool result = ThreatSignatureDatabase.TryTightenFileAcl(tempFile);
                Assert.True(result, "Kullanıcı temp dosyasına ACL sıkılaştırması başarıyla uygulanmalıdır.");
            }
            finally
            {
                try { File.Delete(tempFile); } catch { }
            }
        }

        [Fact]
        public async Task Test_ThreatFeedUpdater_SkipsGracefully_WhenAuthKeyMissing()
        {
            // Görev 2: Auth-Key tanımlı olmadığında API çağrısı yapılmamalı, atlanmalıdır
            var settings = new SettingsService();
            settings.Current.MalwareBazaarApiKey = string.Empty;

            var updater = new ThreatFeedUpdater(null, settings);
            int imported = await updater.UpdateFromMalwareBazaarAsync();

            Assert.Equal(0, imported);
        }

        [Fact]
        public async Task Test_ThreatFeedUpdater_SendsAuthKeyHeader_AndImportsThreats_IntoDatabase()
        {
            // Görev 2: Auth-Key header'ı doğru iletilmeli, dönen JSON çözümlenip SQLite'a aktarılmalı
            string testApiKey = "test_auth_key_secret_dummy";
            var settings = new SettingsService();
            settings.Current.MalwareBazaarApiKey = testApiKey;

            string testDir = Path.Combine(Path.GetTempPath(), "AegisTest_FeedImport_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testDir);
            string testDbPath = Path.Combine(testDir, "threat_signatures.db");

            try
            {
                ThreatSignatureDatabase.ResetForTesting(testDbPath);

                string expectedSha = "ceded191bf677edc18e8b75af350e17bfdb368a65efcc3c8d042b8a012646606";
                bool headerVerified = false;
                bool userAgentVerified = false;

                var mockHandler = new MockHttpMessageHandler(req =>
                {
                    if (req.Headers.TryGetValues("Auth-Key", out var authValues))
                    {
                        headerVerified = authValues.Any(v => v == testApiKey);
                    }

                    if (req.Headers.UserAgent.ToString().Contains("UltronDefender-ThreatFeed"))
                    {
                        userAgentVerified = true;
                    }

                    string mockJson = @"
                    {
                        ""query_status"": ""ok"",
                        ""data"": [
                            {
                                ""sha256_hash"": ""ceded191bf677edc18e8b75af350e17bfdb368a65efcc3c8d042b8a012646606"",
                                ""signature"": ""Mirai"",
                                ""file_type"": ""exe""
                            }
                        ]
                    }";

                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(mockJson, Encoding.UTF8, "application/json")
                    };
                });

                using var httpClient = new HttpClient(mockHandler);
                var updater = new ThreatFeedUpdater(httpClient, settings);

                int imported = await updater.UpdateFromMalwareBazaarAsync();

                Assert.True(headerVerified, "Auth-Key HTTP başlığı mutlaka gönderilmelidir.");
                Assert.True(userAgentVerified, "User-Agent başlığı ayarlanmalıdır.");
                Assert.Equal(1, imported);

                // Veritabanına yazıldığı ve sorgulanabildiği doğrulanmalıdır
                var match = ThreatSignatureDatabase.CheckHash(expectedSha);
                Assert.True(match.IsMatched);
                Assert.Equal("Malware.Mirai", match.Name);
                Assert.Equal("Backdoor/RAT", match.Category);

                // Zaman damgası ayarlara işlenmiş olmalıdır
                Assert.NotNull(settings.Current.LastThreatFeedUpdateUtc);
            }
            finally
            {
                ThreatSignatureDatabase.ResetForTesting();
                try
                {
                    Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                    if (Directory.Exists(testDir))
                    {
                        Directory.Delete(testDir, true);
                    }
                }
                catch { }
            }
        }

        [Fact]
        public void Test_DetectCategory_TagsLinuxAndMacSamples_AsLinuxMac()
        {
            // Görev: elf, sh ve macos örneklerini "Category=Linux/Mac" olarak etiketle
            Assert.Equal("Linux/Mac", ThreatFeedUpdater.DetectCategory("elf", "Mirai"));
            Assert.Equal("Linux/Mac", ThreatFeedUpdater.DetectCategory("sh", "Mirai"));
            Assert.Equal("Linux/Mac", ThreatFeedUpdater.DetectCategory("macos", "Generic"));
            Assert.Equal("Linux/Mac", ThreatFeedUpdater.DetectCategory("macho", "Trojan"));
            Assert.Equal("Linux/Mac", ThreatFeedUpdater.DetectCategory("dylib", "Agent"));
            Assert.Equal("Linux/Mac", ThreatFeedUpdater.DetectCategory("so", "Rootkit"));

            // Windows binaryleri standart kategorilerini korumalıdır
            Assert.Equal("Ransomware", ThreatFeedUpdater.DetectCategory("exe", "LockBit"));
            Assert.Equal("Infostealer", ThreatFeedUpdater.DetectCategory("exe", "RedLine"));
            Assert.Equal("Backdoor/RAT", ThreatFeedUpdater.DetectCategory("exe", "AsyncRAT"));
            Assert.Equal("Cryptominer", ThreatFeedUpdater.DetectCategory("exe", "XMRig"));
            Assert.Equal("Dropper/Loader", ThreatFeedUpdater.DetectCategory("exe", "Emotet"));
            Assert.Equal("Malware", ThreatFeedUpdater.DetectCategory("exe", "UnknownMalware"));
        }

        [Fact]
        public async Task Test_ThreatFeedUpdater_Honors24HourRateLimit_WhenRecentlyUpdated()
        {
            // Görev 3: 24 saat dolmadan tekrar sorgulama yapılmamalıdır (rate limit nezaketi)
            var settings = new SettingsService();
            settings.Current.MalwareBazaarApiKey = "test_key";
            settings.Current.LastThreatFeedUpdateUtc = DateTime.UtcNow.AddHours(-2); // 2 saat önce güncellenmiş

            int requestCount = 0;
            var mockHandler = new MockHttpMessageHandler(req =>
            {
                requestCount++;
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(@"{""query_status"":""ok"",""data"":[]}", Encoding.UTF8, "application/json")
                };
            });

            using var httpClient = new HttpClient(mockHandler);
            var updater = new ThreatFeedUpdater(httpClient, settings);

            // 1. Standart çağrı (force: false) — 24 saat dolmadığı için HTTP çağrısı yapılmamalıdır
            int result = await updater.UpdateFromMalwareBazaarAsync(force: false);
            Assert.Equal(0, result);
            Assert.Equal(0, requestCount);

            // 2. Zorlanmış çağrı (force: true) — rate limit atlanmalı ve HTTP çağrısı yapılmalıdır
            int forcedResult = await updater.UpdateFromMalwareBazaarAsync(force: true);
            Assert.True(requestCount > 0, "force: true iken HTTP çağrısı tetiklenmelidir.");
        }

        [Fact]
        public async Task Test_ThreatFeedUpdater_BootstrapMode_ExecutesTagQueries_AndImportsThreats()
        {
            // Görev 1: İlk açılışta bootstrap yap (get_recent limit=1000 + tag=exe, rat, ransomware, stealer)
            var settings = new SettingsService();
            settings.Current.MalwareBazaarApiKey = "test_key";
            settings.Current.LastThreatFeedUpdateUtc = null; // İlk açılış (Bootstrap tetiklenir)

            string testDir = Path.Combine(Path.GetTempPath(), "AegisTest_Bootstrap_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testDir);
            string testDbPath = Path.Combine(testDir, "threat_signatures.db");

            var requestedQueries = new System.Collections.Generic.List<string>();

            try
            {
                ThreatSignatureDatabase.ResetForTesting(testDbPath);

                var mockHandler = new MockHttpMessageHandler(async req =>
                {
                    // Form içeriğindeki query ve tag parametrelerini yakala
                    string body = req.Content != null ? await req.Content.ReadAsStringAsync() : string.Empty;
                    requestedQueries.Add(body);

                    string mockSample = @"
                    {
                        ""query_status"": ""ok"",
                        ""data"": [
                            {
                                ""sha256_hash"": ""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"",
                                ""signature"": ""LockBit"",
                                ""file_type"": ""exe""
                            },
                            {
                                ""sha256_hash"": ""bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"",
                                ""signature"": ""Mirai"",
                                ""file_type"": ""elf""
                            }
                        ]
                    }";

                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(mockSample, Encoding.UTF8, "application/json")
                    };
                });

                using var httpClient = new HttpClient(mockHandler);
                var updater = new ThreatFeedUpdater(httpClient, settings);

                int imported = await updater.UpdateFromMalwareBazaarAsync();

                // Bootstrap modunda 5 ayrı sorgu (get_recent + 4 tag) gönderilmiş olmalıdır
                Assert.Equal(5, requestedQueries.Count);
                Assert.Contains(requestedQueries, q => q.Contains("query=get_recent") && q.Contains("limit=1000"));
                Assert.Contains(requestedQueries, q => q.Contains("tag=exe"));
                Assert.Contains(requestedQueries, q => q.Contains("tag=rat"));
                Assert.Contains(requestedQueries, q => q.Contains("tag=ransomware"));
                Assert.Contains(requestedQueries, q => q.Contains("tag=stealer"));

                // 2 farklı hash deduplicate edilerek içeri aktarılmış olmalıdır
                Assert.Equal(2, imported);

                // Windows exe -> Ransomware
                var winMatch = ThreatSignatureDatabase.CheckHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                Assert.True(winMatch.IsMatched);
                Assert.Equal("Ransomware", winMatch.Category);

                // Linux elf -> Linux/Mac
                var linuxMatch = ThreatSignatureDatabase.CheckHash("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
                Assert.True(linuxMatch.IsMatched);
                Assert.Equal("Linux/Mac", linuxMatch.Category);
            }
            finally
            {
                ThreatSignatureDatabase.ResetForTesting();
                try
                {
                    Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                    if (Directory.Exists(testDir))
                    {
                        Directory.Delete(testDir, true);
                    }
                }
                catch { }
            }
        }

        [Fact]
        public void Test_WindowsSecurityRegistrationService_HonorsFeatureFlag_DefaultDisabled()
        {
            // Görev 4: EnableWscRegistration varsayılan olarak kapalı olmalı ve WSC kaydını yapmamalıdır
            var settings = new SettingsService();
            Assert.False(settings.Current.EnableWscRegistration, "EnableWscRegistration varsayılan olarak false olmalıdır.");

            var wscService = new WindowsSecurityRegistrationService(settings);

            // Feature flag kapalıyken çağrı güvenle erken dönmeli ve istisna fırlatmamalıdır
            var exception = Record.Exception(() => wscService.RegisterAsSecurityProvider());
            Assert.Null(exception);
        }

        private class MockHttpMessageHandler : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, HttpResponseMessage>? _syncHandler;
            private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>>? _asyncHandler;

            public MockHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
            {
                _syncHandler = handler;
            }

            public MockHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
            {
                _asyncHandler = handler;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (_asyncHandler != null)
                {
                    return _asyncHandler(request);
                }
                return Task.FromResult(_syncHandler!(request));
            }
        }
    }
}
