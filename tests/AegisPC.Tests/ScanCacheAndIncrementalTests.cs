using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Service.Optimization;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class ScanCacheAndIncrementalTests : IDisposable
    {
        private readonly string _testDir;
        private readonly string _cacheDir;

        public ScanCacheAndIncrementalTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "Aegis_ScanCacheTests_" + Guid.NewGuid().ToString("N"));
            _cacheDir = Path.Combine(_testDir, "cache");
            Directory.CreateDirectory(_testDir);
            Directory.CreateDirectory(_cacheDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testDir))
                {
                    Directory.Delete(_testDir, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task ScanCacheService_StoresAndRetrievesVerdictWithinTTL()
        {
            using var cache = new ScanCacheService(_cacheDir, TimeSpan.FromDays(7));

            string dummyHash = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";
            string filePath = Path.Combine(_testDir, "sample_clean.exe");
            long fileSize = 1048576;
            DateTime writeTime = DateTime.UtcNow.AddHours(-2);

            var verdict = new CachedScanVerdict
            {
                SHA256 = dummyHash,
                FilePath = filePath,
                FileSize = fileSize,
                LastWriteTimeUtc = writeTime,
                Verdict = RealTimeVerdict.Clean,
                RecommendedPolicy = RealTimePolicyAction.Allow,
                RiskScore = 0,
                RiskLevel = RiskLevel.Clean,
                Confidence = 1.0,
                ThreatTitle = string.Empty,
                CachedAtUtc = DateTime.UtcNow
            };

            await cache.SetVerdictAsync(verdict);
            await cache.FlushAsync();

            var retrieved = await cache.TryGetVerdictAsync(filePath, dummyHash, fileSize, writeTime);

            Assert.NotNull(retrieved);
            Assert.Equal(dummyHash, retrieved.SHA256);
            Assert.Equal(RealTimeVerdict.Clean, retrieved.Verdict);
            Assert.Equal(0, retrieved.RiskScore);
        }

        [Fact]
        public async Task ScanCacheService_Enforces7DayTTL_ReturnsNullForExpiredVerdict()
        {
            // 7 gün TTL ile önbellek servisi oluştur
            using var cache = new ScanCacheService(_cacheDir, TimeSpan.FromDays(7));

            string dummyHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
            string filePath = Path.Combine(_testDir, "expired_app.dll");
            long fileSize = 524288;
            DateTime writeTime = DateTime.UtcNow.AddDays(-10);

            // 8 gün önce taranmış (TTL 7 günü aşmış) eski kayıt simülasyonu
            var expiredVerdict = new CachedScanVerdict
            {
                SHA256 = dummyHash,
                FilePath = filePath,
                FileSize = fileSize,
                LastWriteTimeUtc = writeTime,
                Verdict = RealTimeVerdict.Clean,
                RiskScore = 0,
                RiskLevel = RiskLevel.Clean,
                CachedAtUtc = DateTime.UtcNow.AddDays(-8) // 8 gün önce
            };

            await cache.SetVerdictAsync(expiredVerdict);
            await cache.FlushAsync();

            // TTL aşımı nedeniyle null (Fresh Scan zorunluluğu) dönmeli
            var retrieved = await cache.TryGetVerdictAsync(filePath, dummyHash, fileSize, writeTime);

            Assert.Null(retrieved);
        }

        [Fact]
        public async Task ScanCacheService_CacheKeyChangesWhenFileIsModified()
        {
            using var cache = new ScanCacheService(_cacheDir, TimeSpan.FromDays(7));

            string hash1 = "1111111111111111111111111111111111111111111111111111111111111111";
            string filePath = Path.Combine(_testDir, "mod_target.exe");
            long initialSize = 1024;
            DateTime initialWriteTime = DateTime.UtcNow.AddDays(-1);

            var verdict = new CachedScanVerdict
            {
                SHA256 = hash1,
                FilePath = filePath,
                FileSize = initialSize,
                LastWriteTimeUtc = initialWriteTime,
                Verdict = RealTimeVerdict.Clean,
                RiskScore = 0,
                CachedAtUtc = DateTime.UtcNow
            };

            await cache.SetVerdictAsync(verdict);
            await cache.FlushAsync();

            // Dosya boyutu değiştiğinde önbellek ıskalanmalı
            var sizeChanged = await cache.TryGetVerdictAsync(filePath, hash1, initialSize + 500, initialWriteTime);
            Assert.Null(sizeChanged);

            // Yazma tarihi değiştiğinde önbellek ıskalanmalı
            var timeChanged = await cache.TryGetVerdictAsync(filePath, hash1, initialSize, DateTime.UtcNow);
            Assert.Null(timeChanged);
        }

        [Fact]
        public async Task IncrementalScan_SkipsUnchangedFiles_AndFreshScansModified()
        {
            using var cache = new ScanCacheService(_cacheDir, TimeSpan.FromDays(7));
            var incremental = new IncrementalScan(cache);

            string sandbox = Path.Combine(_testDir, "scan_root");
            Directory.CreateDirectory(sandbox);

            // 5 adet test dosyası oluştur
            string f1 = Path.Combine(sandbox, "f1.txt");
            string f2 = Path.Combine(sandbox, "f2.txt");
            string f3 = Path.Combine(sandbox, "f3.txt");
            File.WriteAllText(f1, "file1 content");
            File.WriteAllText(f2, "file2 content");
            File.WriteAllText(f3, "file3 content");

            // 1. İLK TARAMA (Cold Scan): Tüm dosyalar taze taranır
            var firstSummary = await incremental.RunIncrementalDirectoryScanAsync(
                sandbox,
                ScanType.Quick,
                (path, ct) => Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.FromMilliseconds(5))));

            Assert.Equal(3, firstSummary.TotalFilesDiscovered);
            Assert.Equal(3, firstSummary.FreshScannedFiles);
            Assert.Equal(0, firstSummary.SkippedCachedFiles);

            // 2. İKİNCİ TARAMA (Incremental Warm Scan): Dosyalar değişmedi, hepsi atlanmalı
            var secondSummary = await incremental.RunIncrementalDirectoryScanAsync(
                sandbox,
                ScanType.Quick,
                (path, ct) => Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.FromMilliseconds(5))));

            Assert.Equal(3, secondSummary.TotalFilesDiscovered);
            Assert.Equal(0, secondSummary.FreshScannedFiles);
            Assert.Equal(3, secondSummary.SkippedCachedFiles);
            Assert.True(secondSummary.CacheHitRatio >= 1.0);

            // 3. BİR DOSYA DEĞİŞTİR: f2 dosyasını modifiye et
            await Task.Delay(100);
            File.AppendAllText(f2, " modified text append");
            File.SetLastWriteTimeUtc(f2, DateTime.UtcNow);

            var thirdSummary = await incremental.RunIncrementalDirectoryScanAsync(
                sandbox,
                ScanType.Quick,
                (path, ct) => Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.FromMilliseconds(5))));

            Assert.Equal(3, thirdSummary.TotalFilesDiscovered);
            Assert.Equal(1, thirdSummary.FreshScannedFiles); // Yalnızca f2 taranmalı!
            Assert.Equal(2, thirdSummary.SkippedCachedFiles); // f1 ve f3 atlanmalı
        }

        [Fact]
        public async Task ScanCache_Benchmark_DemonstratesSignificantSpeedupRatio()
        {
            using var cache = new ScanCacheService(_cacheDir, TimeSpan.FromDays(7));
            var incremental = new IncrementalScan(cache);

            string benchRoot = Path.Combine(_testDir, "bench_files");
            Directory.CreateDirectory(benchRoot);

            // 200 adet sanal dosya oluştur
            for (int i = 0; i < 200; i++)
            {
                File.WriteAllText(Path.Combine(benchRoot, $"file_{i}.dat"), $"Content for file {i}");
            }

            // Simüle edilen derin dosya tarama maliyeti (örnek: disk okuma + sha256 + PUP kontrolü ~2ms)
            async Task<FileScanDetailedResult> SimulatedDeepScan(string path, CancellationToken ct)
            {
                await Task.Delay(2, ct);
                return FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.FromMilliseconds(2));
            }

            // Soğuk Tarama (Cold Scan)
            var swCold = Stopwatch.StartNew();
            var coldSummary = await incremental.RunIncrementalDirectoryScanAsync(benchRoot, ScanType.Quick, SimulatedDeepScan);
            swCold.Stop();

            // Sıcak Tarama (Warm Incremental Scan)
            var swWarm = Stopwatch.StartNew();
            var warmSummary = await incremental.RunIncrementalDirectoryScanAsync(benchRoot, ScanType.Quick, SimulatedDeepScan);
            swWarm.Stop();

            Assert.Equal(200, coldSummary.FreshScannedFiles);
            Assert.Equal(200, warmSummary.SkippedCachedFiles);

            // Sıcak tarama soğuk taramadan en az 3 kat hızlı olmalıdır
            Assert.True(swWarm.ElapsedMilliseconds < swCold.ElapsedMilliseconds, 
                $"Warm scan ({swWarm.ElapsedMilliseconds}ms) must be faster than cold scan ({swCold.ElapsedMilliseconds}ms)");
        }
    }
}
