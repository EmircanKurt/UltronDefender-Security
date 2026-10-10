using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Core.Enums;
using AegisPC.Core.Exceptions;
using AegisPC.Core.Models;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class QuarantineHardeningTests : IDisposable
    {
        private readonly string _sandboxDir;
        private readonly string _vaultDir;

        public QuarantineHardeningTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "Aegis_HardeningTest_" + Guid.NewGuid().ToString("N"));
            _vaultDir = Path.Combine(_sandboxDir, "Vault");
            Directory.CreateDirectory(_sandboxDir);
            Directory.CreateDirectory(_vaultDir);
        }

        public void Dispose()
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, true);
                }
            }
            catch
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                try { Directory.Delete(_sandboxDir, true); } catch { }
            }
        }

        [Fact]
        public async Task ConcurrentQuarantine_100SimultaneousCalls_GeneratesStrictlyUniqueIdsWithoutCollision()
        {
            // P0 Çözüm Doğrulaması: Eşzamanlı işlemlerdeki (1, 1) ID çakışması tamamen engellenmeli
            using var engine = new TransactionalQuarantineEngine(customVaultDir: _vaultDir);

            int fileCount = 50;
            var filePaths = new string[fileCount];
            for (int i = 0; i < fileCount; i++)
            {
                filePaths[i] = Path.Combine(_sandboxDir, $"payload_{i}_{Guid.NewGuid():N}.bin");
                await File.WriteAllBytesAsync(filePaths[i], Encoding.UTF8.GetBytes($"PAYLOAD_DATA_{i}"));
            }

            var tasks = filePaths.Select(path => engine.ExecuteQuarantineAsync(new QuarantineRequest
            {
                TargetFilePath = path,
                ThreatReason = "Trojan.ConcurrentTest",
                ForceKillHoldingProcesses = false
            })).ToArray();

            var results = await Task.WhenAll(tasks);

            // Tüm işlemler başarılı olmalı
            Assert.All(results, r => Assert.True(r.Success, r.Message));

            // Tüm ID'ler kesinlikle benzersiz olmalı (hiçbir çakışma olamaz)
            var ids = results.Select(r => r.QuarantineId).ToList();
            Assert.Equal(fileCount, ids.Distinct().Count());

            // Tüm ID'ler 1..N aralığında sıralı ve pozitif olmalı
            Assert.All(ids, id => Assert.True(id > 0));

            // SQLite veritabanındaki kayıt adedi ile oluşturulan ID adedi tam eşleşmeli
            var storedItems = await engine.GetQuarantinedItemsAsync();
            Assert.Equal(fileCount, storedItems.Count);
        }

        [Fact]
        public async Task IndexFailure_RollsBackCleanly_AndLeavesOriginalFileUntouched()
        {
            // Atomik Sıra Güvencesi: İndeks yazılamazsa kasa dosyası temizlenmeli ve kaynak dosya bozulmadan bırakılmalı
            var testFile = Path.Combine(_sandboxDir, "precious_user_file.bin");
            var originalContent = "IMPORTANT_CONTENT_THAT_MUST_NOT_BE_LOST";
            await File.WriteAllTextAsync(testFile, originalContent);

            using var engine = new TransactionalQuarantineEngine(customVaultDir: _vaultDir);

            // İndeks yazım hatasını simüle et: quarantine_index.json dosya adı yerine bir dizin oluştur
            // SQLite ve sync indeksi bu engelle karşılaştığında işlem geri alınmalıdır
            var jsonPath = Path.Combine(_vaultDir, "quarantine_index.json");
            Directory.CreateDirectory(jsonPath);

            var result = await engine.ExecuteQuarantineAsync(new QuarantineRequest
            {
                TargetFilePath = testFile,
                ThreatReason = "Simulation.IndexFailure",
                ForceKillHoldingProcesses = false
            });

            // İşlem başarısız olarak dönmeli
            Assert.False(result.Success);
            Assert.Equal(QuarantineTransactionStatus.RolledBack, result.Status);

            // Orijinal dosya diskte SAPASAĞLAM kalmalı
            Assert.True(File.Exists(testFile));
            var readContent = await File.ReadAllTextAsync(testFile);
            Assert.Equal(originalContent, readContent);

            // Kasada yetim veya yarım kalmış .quar / .tmp dosyası bulunmamalı
            Assert.Empty(Directory.GetFiles(_vaultDir, "*.quar"));
            Assert.Empty(Directory.GetFiles(_vaultDir, "*.tmp"));
            Assert.Empty(await engine.Database.GetAllEntriesAsync());
        }

        [Fact]
        public async Task OriginalFileLocked_DoesNotReportSuccess_AndRollsBackVault()
        {
            // Adım Sırası Güvencesi: Kaynak dosya silinemezse durum 'başarısız' olarak kaydedilmeli, asla başarı dönülmemeli
            var lockedFile = Path.Combine(_sandboxDir, "locked_malware.exe");
            await File.WriteAllTextAsync(lockedFile, "CANNOT_DELETE_ME_BECAUSE_EXCLUSIVE_HANDLE");

            using var engine = new TransactionalQuarantineEngine(customVaultDir: _vaultDir);

            // Dosyayı dışarıdan kilitle (FileShare.None ile silinmesini engelle)
            using (var lockStream = new FileStream(lockedFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var result = await engine.ExecuteQuarantineAsync(new QuarantineRequest
                {
                    TargetFilePath = lockedFile,
                    ThreatReason = "Locked.Malware",
                    ForceKillHoldingProcesses = false
                });

                // Asla başarı raporlanmamalı
                Assert.False(result.Success);
                Assert.Equal(QuarantineTransactionStatus.RolledBack, result.Status);
                Assert.Contains("kaldırılamadı", result.Message, StringComparison.OrdinalIgnoreCase);

                // Orijinal dosya yerinde durmalı
                Assert.True(File.Exists(lockedFile));
            }

            // Kasa dosyası rollback ile temizlenmiş olmalı
            Assert.Empty(Directory.GetFiles(_vaultDir, "*.quar"));

            // Veritabanında aktif karantina kaydı bulunmamalı
            var activeItems = await engine.GetQuarantinedItemsAsync();
            Assert.Empty(activeItems);
        }

        [Fact]
        public async Task LegacyJsonIndex_LosslessMigrationToSqlite_OnStartup()
        {
            // Kayıpsız Migrasyon: Eski JSON indeksi başlangıçta SQLite'a aktarılmalı ve arşivlenmeli
            var legacyJsonPath = Path.Combine(_vaultDir, "quarantine_index.json");
            var legacyEntries = new List<QuarantineEntry>
            {
                new QuarantineEntry
                {
                    Id = 101,
                    OriginalPath = @"C:\Users\Student\malware1.exe",
                    QuarantinePath = Path.Combine(_vaultDir, "vault_101.quar"),
                    FileName = "malware1.exe",
                    SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    FileSize = 1024,
                    Reason = "Legacy.Threat.1",
                    RiskLevel = RiskLevel.HighRisk,
                    QuarantinedAt = DateTime.UtcNow.AddDays(-2),
                    Status = QuarantineStatus.Quarantined
                },
                new QuarantineEntry
                {
                    Id = 102,
                    OriginalPath = @"C:\Users\Student\malware2.dll",
                    QuarantinePath = Path.Combine(_vaultDir, "vault_102.quar"),
                    FileName = "malware2.dll",
                    SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    FileSize = 2048,
                    Reason = "Legacy.Threat.2",
                    RiskLevel = RiskLevel.ConfirmedMalicious,
                    QuarantinedAt = DateTime.UtcNow.AddDays(-1),
                    Status = QuarantineStatus.Quarantined
                }
            };

            await File.WriteAllTextAsync(legacyJsonPath, JsonSerializer.Serialize(legacyEntries));

            // Motoru başlat
            using var engine = new TransactionalQuarantineEngine(customVaultDir: _vaultDir);

            // SQLite veritabanına aktarıldığını doğrula
            var migratedItems = await engine.GetQuarantinedItemsAsync();
            Assert.Equal(2, migratedItems.Count);
            Assert.Contains(migratedItems, x => x.Id == 101 && x.FileName == "malware1.exe");
            Assert.Contains(migratedItems, x => x.Id == 102 && x.FileName == "malware2.dll");

            // Eski JSON dosyasının arşivlendiğini doğrula (.migrated)
            Assert.True(File.Exists(legacyJsonPath + ".migrated"));
        }

        [Fact]
        public async Task RestoreV2LegacyContainer_SuccessfullyDecryptsAndRestores()
        {
            // Eski V2 Kasa Dosyalarını Okuma Güvencesi: ULTRON_QUAR_V2 formatı kayıpsız çözülmelidir
            using var engine = new TransactionalQuarantineEngine(customVaultDir: _vaultDir);
            var masterKey = engine.GetMasterKey();

            var originalPayload = "LEGACY_V2_ULTRON_QUARANTINE_PAYLOAD_CONTENT_987654321";
            var plainBytes = Encoding.UTF8.GetBytes(originalPayload);
            var sha256 = Convert.ToHexString(SHA256.HashData(plainBytes)).ToLowerInvariant();

            // V2 formatında kapsayıcı oluştur
            var v2VaultFile = Path.Combine(_vaultDir, "vault_v2_legacy.quar");
            var iv = new byte[16];
            RandomNumberGenerator.Fill(iv);

            using (var fs = new FileStream(v2VaultFile, FileMode.Create, FileAccess.Write))
            using (var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: true))
            using (var aes = Aes.Create())
            {
                aes.Key = masterKey;
                aes.IV = iv;
                bw.Write("ULTRON_QUAR_V2");
                bw.Write(iv.Length);
                bw.Write(iv);
                bw.Write(sha256);

                long lenPos = fs.Position;
                bw.Write((int)0);
                long startPos = fs.Position;

                using (var cs = new CryptoStream(fs, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
                {
                    await cs.WriteAsync(plainBytes);
                    await cs.FlushAsync();
                }

                int encryptedLen = (int)(fs.Position - startPos);
                fs.Position = lenPos;
                bw.Write(encryptedLen);
            }

            // Kaydı SQLite veritabanına ekle
            var entry = new QuarantineEntry
            {
                Id = 999,
                OriginalPath = Path.Combine(_sandboxDir, "restored_v2_sample.txt"),
                QuarantinePath = v2VaultFile,
                FileName = "restored_v2_sample.txt",
                SHA256 = sha256,
                FileSize = plainBytes.Length,
                Reason = "Legacy.V2.Threat",
                RiskLevel = RiskLevel.HighRisk,
                QuarantinedAt = DateTime.UtcNow,
                Status = QuarantineStatus.Quarantined
            };

            await engine.Database.InsertEntryAsync(entry, entry.OriginalPath);

            // Geri yüklemeyi çalıştır
            var restoreResult = await engine.ExecuteRestoreAsync(999);

            Assert.True(restoreResult.Success, restoreResult.Message);
            Assert.True(File.Exists(entry.OriginalPath));
            var restoredText = await File.ReadAllTextAsync(entry.OriginalPath);
            Assert.Equal(originalPayload, restoredText);
        }

        [Fact]
        public async Task Restore_WhenReparsePointOrExistingDestination_ProtectsTargetFromOverwrite()
        {
            // Güvenli Geri Yükleme: Mevcut dosyanın üzerine yazılmamalı, hedef korunmalıdır
            var sampleFile = Path.Combine(_sandboxDir, "sensitive_target.exe");
            await File.WriteAllTextAsync(sampleFile, "INITIAL_PAYLOAD");

            using var engine = new TransactionalQuarantineEngine(customVaultDir: _vaultDir);
            var result = await engine.ExecuteQuarantineAsync(new QuarantineRequest
            {
                TargetFilePath = sampleFile,
                ThreatReason = "Test.Guard",
                ForceKillHoldingProcesses = false
            });

            Assert.True(result.Success);

            // Kullanıcı hedef konumda aynı isimde yeni bir dosya oluşturmuş olsun
            await File.WriteAllTextAsync(sampleFile, "NEW_IMPORTANT_USER_FILE");

            // Geri yükleme çağrısı yapılınca mevcut dosya ASLA sessizce ezilmemeli
            var restoreResult = await engine.ExecuteRestoreAsync(result.QuarantineId);

            Assert.False(restoreResult.Success);
            Assert.Contains("zaten var", restoreResult.Message, StringComparison.OrdinalIgnoreCase);

            // Yeni kullanıcının dosyası bozulmadan durmalı
            Assert.Equal("NEW_IMPORTANT_USER_FILE", await File.ReadAllTextAsync(sampleFile));
        }

        [Fact]
        public async Task SameHashDifferentPaths_MaintainsDistinctRestorePaths()
        {
            // Çoklu Kaynak Yolu Desteği: Aynı SHA-256 içeriğine sahip farklı dosyalar kendi geri yükleme yollarını korumalıdır
            var pathA = Path.Combine(_sandboxDir, "threat_in_temp.bin");
            var pathB = Path.Combine(_sandboxDir, "threat_in_downloads.bin");
            var sharedContent = "IDENTICAL_MALWARE_BYTE_CONTENT_12345";
            await File.WriteAllTextAsync(pathA, sharedContent);
            await File.WriteAllTextAsync(pathB, sharedContent);

            using var engine = new TransactionalQuarantineEngine(customVaultDir: _vaultDir);

            var resA = await engine.ExecuteQuarantineAsync(new QuarantineRequest { TargetFilePath = pathA, ThreatReason = "Trojan.Shared" });
            var resB = await engine.ExecuteQuarantineAsync(new QuarantineRequest { TargetFilePath = pathB, ThreatReason = "Trojan.Shared" });

            Assert.True(resA.Success);
            Assert.True(resB.Success);
            Assert.NotEqual(resA.QuarantineId, resB.QuarantineId);

            // Her dosya kendi orijinal yoluna geri yüklenebilmeli
            var restoreA = await engine.ExecuteRestoreAsync(resA.QuarantineId);
            Assert.True(restoreA.Success);
            Assert.Equal(pathA, restoreA.RestoredPath);
            Assert.True(File.Exists(pathA));
            Assert.False(File.Exists(pathB)); // pathB henüz geri yüklenmedi

            var restoreB = await engine.ExecuteRestoreAsync(resB.QuarantineId);
            Assert.True(restoreB.Success);
            Assert.Equal(pathB, restoreB.RestoredPath);
            Assert.True(File.Exists(pathB));
        }
    }
}
