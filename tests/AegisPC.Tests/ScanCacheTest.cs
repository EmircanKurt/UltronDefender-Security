using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Service.Optimization;
using Xunit;

namespace AegisPC.Tests
{
    /// <summary>
    /// Yüksek Başarımlı Akıllı Tarama Önbelleği (ScanCacheService) ve Artımlı Tarama (IncrementalScan) Test Paketi.
    /// Cache Hit, Cache Miss, 7 Günlük TTL zaman aşımı, dosya değişikliği geçersiz kılma (invalidation)
    /// ve L1 Bellek + L2 SQLite kalıcılık katmanlarını test eder.
    /// </summary>
    [Collection("SequentialDiskTests")]
    public class ScanCacheTest : IDisposable
    {
        private readonly string _tempCacheDir;

        public ScanCacheTest()
        {
            _tempCacheDir = Path.Combine(Path.GetTempPath(), "Aegis_ScanCacheTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_tempCacheDir);
        }

        [Fact]
        public async Task ScanCache_CacheHit_ReturnsCachedVerdictImmediately()
        {
            using var cache = new ScanCacheService(_tempCacheDir, TimeSpan.FromDays(7));

            string filePath = @"C:\Users\PC\Documents\clean_report.pdf";
            string sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            long fileSize = 102400;
            DateTime lastWrite = new DateTime(2026, 9, 8, 10, 0, 0, DateTimeKind.Utc);

            // 1. Önce önbelleğe yaz
            var verdict = new CachedScanVerdict
            {
                FilePath = filePath,
                SHA256 = sha256,
                FileSize = fileSize,
                LastWriteTimeUtc = lastWrite,
                Verdict = RealTimeVerdict.Clean,
                RecommendedPolicy = RealTimePolicyAction.Allow,
                RiskScore = 0,
                RiskLevel = RiskLevel.Clean,
                Confidence = 1.0,
                CachedAtUtc = DateTime.UtcNow
            };

            await cache.SetVerdictAsync(verdict);
            await cache.FlushAsync();

            // 2. Önbellekten sorgula (Cache Hit)
            var cachedResult = await cache.TryGetVerdictAsync(filePath, sha256, fileSize, lastWrite);

            Assert.NotNull(cachedResult);
            Assert.Equal(RealTimeVerdict.Clean, cachedResult.Verdict);
            Assert.Equal(0, cachedResult.RiskScore);
            Assert.Equal(RiskLevel.Clean, cachedResult.RiskLevel);
        }

        [Fact]
        public async Task ScanCache_CacheMiss_WhenFileModifiedOrNew()
        {
            using var cache = new ScanCacheService(_tempCacheDir, TimeSpan.FromDays(7));

            string filePath = @"C:\Users\PC\Documents\app.exe";
            string sha256 = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
            long fileSize = 50000;
            DateTime originalWrite = new DateTime(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);

            // Henüz önbellekte olmayan dosya
            var missResult = await cache.TryGetVerdictAsync(filePath, sha256, fileSize, originalWrite);
            Assert.Null(missResult);

            // Önbelleğe kaydet
            await cache.SetVerdictAsync(new CachedScanVerdict
            {
                FilePath = filePath,
                SHA256 = sha256,
                FileSize = fileSize,
                LastWriteTimeUtc = originalWrite,
                Verdict = RealTimeVerdict.Clean,
                CachedAtUtc = DateTime.UtcNow
            });
            await cache.FlushAsync();

            // Dosya değiştirilmiş (LastWriteTimeUtc güncellenmiş)
            DateTime modifiedWrite = originalWrite.AddHours(2);
            var modResult = await cache.TryGetVerdictAsync(filePath, sha256, fileSize, modifiedWrite);
            Assert.Null(modResult);

            // Dosya boyutu değişmiş
            var sizeResult = await cache.TryGetVerdictAsync(filePath, sha256, fileSize + 100, originalWrite);
            Assert.Null(sizeResult);
        }

        [Fact]
        public async Task ScanCache_TTLExpiration_InvalidatesEntriesOlderThan7Days()
        {
            // TTL 200 milisaniye olan test önbelleği oluştur
            using var cache = new ScanCacheService(_tempCacheDir, TimeSpan.FromMilliseconds(200));

            string filePath = @"C:\Users\PC\Documents\temp_scan.dll";
            string sha256 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
            long fileSize = 2048;
            DateTime lastWrite = DateTime.UtcNow;

            await cache.SetVerdictAsync(new CachedScanVerdict
            {
                FilePath = filePath,
                SHA256 = sha256,
                FileSize = fileSize,
                LastWriteTimeUtc = lastWrite,
                Verdict = RealTimeVerdict.Clean,
                CachedAtUtc = DateTime.UtcNow
            });
            await cache.FlushAsync();

            // TTL dolmadan önce: Hit
            var hitBefore = await cache.TryGetVerdictAsync(filePath, sha256, fileSize, lastWrite);
            Assert.NotNull(hitBefore);

            // TTL süresini bekle
            await Task.Delay(350);

            // TTL dolduktan sonra: Miss
            var hitAfter = await cache.TryGetVerdictAsync(filePath, sha256, fileSize, lastWrite);
            Assert.Null(hitAfter);
        }

        [Fact]
        public async Task ScanCache_IncrementalScan_FiltersChangedFilesAccurately()
        {
            string sandbox = Path.Combine(_tempCacheDir, "IncrementalSandbox");
            Directory.CreateDirectory(sandbox);

            using var cache = new ScanCacheService(_tempCacheDir, TimeSpan.FromDays(7));
            var incremental = new IncrementalScan(cache);

            string file1 = Path.Combine(sandbox, "f1.txt");
            string file2 = Path.Combine(sandbox, "f2.txt");

            await File.WriteAllTextAsync(file1, "Initial file 1 content");
            await File.WriteAllTextAsync(file2, "Initial file 2 content");

            // 1. İlk Tarama (Cold Scan)
            var scan1 = await incremental.RunIncrementalDirectoryScanAsync(
                sandbox,
                ScanType.Quick,
                (path, ct) => Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.FromMilliseconds(5))));

            Assert.Equal(2, scan1.TotalFilesDiscovered);
            Assert.Equal(2, scan1.FreshScannedFiles);
            Assert.Equal(0, scan1.SkippedCachedFiles);

            // 2. İkinci Tarama (Değişmedi, atlanmalı)
            var scan2 = await incremental.RunIncrementalDirectoryScanAsync(
                sandbox,
                ScanType.Quick,
                (path, ct) => Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.FromMilliseconds(5))));

            Assert.Equal(2, scan2.TotalFilesDiscovered);
            Assert.Equal(0, scan2.FreshScannedFiles);
            Assert.Equal(2, scan2.SkippedCachedFiles);
            Assert.True(scan2.CacheHitRatio >= 1.0);

            // 3. Bir dosyayı güncelle
            await Task.Delay(50);
            await File.AppendAllTextAsync(file2, "\r\nUpdated line.");
            File.SetLastWriteTimeUtc(file2, DateTime.UtcNow);

            var scan3 = await incremental.RunIncrementalDirectoryScanAsync(
                sandbox,
                ScanType.Quick,
                (path, ct) => Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.FromMilliseconds(5))));

            Assert.Equal(2, scan3.TotalFilesDiscovered);
            Assert.Equal(1, scan3.FreshScannedFiles); // Yalnızca f2 taranmalı
            Assert.Equal(1, scan3.SkippedCachedFiles); // f1 atlanmalı
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempCacheDir))
                {
                    Directory.Delete(_tempCacheDir, recursive: true);
                }
            }
            catch { }
        }
    }
}
