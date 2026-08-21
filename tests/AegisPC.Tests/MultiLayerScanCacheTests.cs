using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Core.Enums;
using AegisPC.Security.Caching;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class MultiLayerScanCacheTests : IDisposable
    {
        private readonly string _sandboxDir;
        private readonly MultiLayerScanCache _cache;

        public MultiLayerScanCacheTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "AegisCacheTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);
            _cache = new MultiLayerScanCache(_sandboxDir);
        }

        public void Dispose()
        {
            try
            {
                _cache.Clear();
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Test_L1_CacheHit_ReturnsCachedVerdict()
        {
            var sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            var filePath = Path.Combine(_sandboxDir, "sample.exe");
            var now = DateTime.UtcNow;

            var verdict = new CachedScanVerdict
            {
                SHA256 = sha256,
                FilePath = filePath,
                FileSize = 1024,
                LastWriteTimeUtc = now,
                Verdict = RealTimeVerdict.Clean,
                RecommendedPolicy = RealTimePolicyAction.Allow,
                RiskScore = 0,
                RiskLevel = RiskLevel.Clean,
                Confidence = 0.99
            };

            await _cache.SetVerdictAsync(verdict);

            var cached = await _cache.TryGetVerdictAsync(filePath, sha256, 1024, now);

            Assert.NotNull(cached);
            Assert.Equal(RealTimeVerdict.Clean, cached.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, cached.RecommendedPolicy);
            Assert.Equal(0, cached.RiskScore);
        }

        [Fact]
        public async Task Test_Cache_InvalidatesOnTimestampOrSizeChange()
        {
            var sha256 = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";
            var filePath = Path.Combine(_sandboxDir, "modified_app.exe");
            var initialTime = DateTime.UtcNow.AddHours(-1);

            var verdict = new CachedScanVerdict
            {
                SHA256 = sha256,
                FilePath = filePath,
                FileSize = 2048,
                LastWriteTimeUtc = initialTime,
                Verdict = RealTimeVerdict.Clean,
                RecommendedPolicy = RealTimePolicyAction.Allow,
                RiskScore = 0,
                RiskLevel = RiskLevel.Clean
            };

            await _cache.SetVerdictAsync(verdict);

            // 1. Same timestamp & size -> HIT
            var hit = await _cache.TryGetVerdictAsync(filePath, sha256, 2048, initialTime);
            Assert.NotNull(hit);

            // 2. Modified timestamp -> MISS (must be re-scanned)
            var modifiedTime = DateTime.UtcNow;
            var missTime = await _cache.TryGetVerdictAsync(filePath, sha256, 2048, modifiedTime);
            Assert.Null(missTime);

            // 3. Modified size -> MISS
            var missSize = await _cache.TryGetVerdictAsync(filePath, sha256, 4096, initialTime);
            Assert.Null(missSize);
        }

        [Fact]
        public async Task Test_L2_DiskPersistence_SurvivesInstanceRestart()
        {
            var sha256 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
            var filePath = Path.Combine(_sandboxDir, "persisted_app.exe");
            var writeTime = DateTime.UtcNow;

            var verdict = new CachedScanVerdict
            {
                SHA256 = sha256,
                FilePath = filePath,
                FileSize = 5120,
                LastWriteTimeUtc = writeTime,
                Verdict = RealTimeVerdict.ConfirmedMalicious,
                RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine,
                RiskScore = 95,
                RiskLevel = RiskLevel.ConfirmedMalicious,
                ThreatTitle = "Ransomware.TestDropper"
            };

            await _cache.SetVerdictAsync(verdict);

            // Wait 100ms for background L2 persistence task
            await Task.Delay(150);

            // Create a second new cache instance pointing to the same storage directory
            var secondCacheInstance = new MultiLayerScanCache(_sandboxDir);

            var recoveredVerdict = await secondCacheInstance.TryGetVerdictAsync(filePath, sha256, 5120, writeTime);

            Assert.NotNull(recoveredVerdict);
            Assert.Equal(RealTimeVerdict.ConfirmedMalicious, recoveredVerdict.Verdict);
            Assert.Equal(95, recoveredVerdict.RiskScore);
            Assert.Equal("Ransomware.TestDropper", recoveredVerdict.ThreatTitle);
        }

        [Fact]
        public async Task Test_InvalidateAsync_RemovesEntry()
        {
            var sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
            var filePath = Path.Combine(_sandboxDir, "deleted_app.exe");
            var writeTime = DateTime.UtcNow;

            var verdict = new CachedScanVerdict
            {
                SHA256 = sha256,
                FilePath = filePath,
                FileSize = 100,
                LastWriteTimeUtc = writeTime,
                Verdict = RealTimeVerdict.Clean
            };

            await _cache.SetVerdictAsync(verdict);
            Assert.NotNull(await _cache.TryGetVerdictAsync(filePath, sha256, 100, writeTime));

            // Invalidate file
            await _cache.InvalidateAsync(filePath);

            Assert.Null(await _cache.TryGetVerdictAsync(filePath, sha256, 100, writeTime));
        }
    }
}
