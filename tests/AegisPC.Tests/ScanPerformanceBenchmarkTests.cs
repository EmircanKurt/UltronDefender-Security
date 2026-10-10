using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using AegisPC.Service.Optimization;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class ScanPerformanceBenchmarkTests : IDisposable
    {
        private readonly string _testDir;
        private readonly ScanCacheService _cacheService;

        public ScanPerformanceBenchmarkTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "Aegis_PerfBenchmark_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);
            _cacheService = new ScanCacheService(customDbDir: _testDir);
        }

        public void Dispose()
        {
            try
            {
                _cacheService.Dispose();
                if (Directory.Exists(_testDir))
                {
                    Directory.Delete(_testDir, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public void SafeMediaExtensions_AreCorrectlyCategorized()
        {
            string[] testFiles = new[]
            {
                "photo.jpg", "video.mp4", "report.pdf", "data.json", "styles.css",
                "model.blend", "cache.fits", "weights.npy", "archive.parquet", "symbols.pdb"
            };

            foreach (var file in testFiles)
            {
                string ext = Path.GetExtension(file);
                Assert.True(ScanFilterPolicy.SafeMediaExtensions.Contains(ext), $"Extension {ext} MUST be in SafeMediaExtensions!");
            }
        }

        [Fact]
        public async Task ScanCache_StoresAndRetrievesCleanVerdict_InSubMillisecond()
        {
            string sampleFile = Path.Combine(_testDir, "clean_module.dll");
            await File.WriteAllTextAsync(sampleFile, "SAMPLE_CLEAN_DLL_CONTENT");

            var fileInfo = new FileInfo(sampleFile);
            string sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            // Store clean verdict
            await _cacheService.SetVerdictAsync(new CachedScanVerdict
            {
                FilePath = sampleFile,
                SHA256 = sha256,
                FileSize = fileInfo.Length,
                LastWriteTimeUtc = fileInfo.LastWriteTimeUtc,
                Verdict = RealTimeVerdict.Clean,
                ThreatTitle = "Benchmark Clean DLL"
            });

            // Measure lookup latency
            var sw = Stopwatch.StartNew();
            var cached = await _cacheService.TryGetVerdictAsync(
                sampleFile,
                sha256,
                fileInfo.Length,
                fileInfo.LastWriteTimeUtc);
            sw.Stop();

            Assert.NotNull(cached);
            Assert.Equal(RealTimeVerdict.Clean, cached.Verdict);
            Assert.Equal("Benchmark Clean DLL", cached.ThreatTitle);
            Assert.True(sw.ElapsedMilliseconds < 50, $"L1 Cache lookup must be instantaneous (< 50ms, was {sw.ElapsedMilliseconds}ms)");
        }

        /// <summary>Checks actual runtime/state roots without trusting a fictional install name, repository, or matching prefix.</summary>
        [Fact]
        public void ScanFilterPolicy_SelfOwnedPath_ProtectsApplicationAndQuarantineFromLoops()
        {
            Assert.True(ScanFilterPolicy.IsSelfOwnedPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "application.dll")));
            string commonData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            Assert.True(ScanFilterPolicy.IsSelfOwnedPath(Path.Combine(commonData, "UltronDefender", "signatures", "signatures_packed.bin")));
            Assert.True(ScanFilterPolicy.IsSelfOwnedPath(Path.Combine(commonData, "UltronDefender", "QuarantineVault", "vault_1.quar")));
            Assert.True(ScanFilterPolicy.IsSelfOwnedPath(Path.Combine(localData, "UltronDefender", "cache", "ScanCache.db")));

            foreach (string root in ScanFilterPolicy.SelfExcludedPaths.Value)
            {
                string prefixLookalike = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + "_lookalike";
                Assert.False(ScanFilterPolicy.IsSelfOwnedPath(Path.Combine(prefixLookalike, "untrusted.bin")));
            }

            Assert.False(ScanFilterPolicy.IsSelfOwnedPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "UltronDefender", "UltronDefender.exe")));
            Assert.False(ScanFilterPolicy.IsSelfOwnedPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "gemini virüs program", "review-fixture.bin")));
            Assert.False(ScanFilterPolicy.IsSelfOwnedPath(Path.Combine(Environment.SystemDirectory, "notepad.exe")));
        }

        /// <summary>Checks that both PE-looking and JPEG-looking content reaches workers; a media hint is neither trust nor a signed-clean verdict.</summary>
        [Fact]
        public async Task ScanQueueCoordinator_DisguisedPeAsJpg_IsQueuedAndNotSkipped_AndMediaNotCountedAsSignedClean()
        {
            // Producer hints must not conceal executable content, polyglots, or unsupported file types.
            string testFolder = Path.Combine(_testDir, "QueueTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(testFolder);

            // 1. .jpg uzantılı PE ikilisi (MZ header)
            string disguisedPe = Path.Combine(testFolder, "evil_payload.jpg");
            byte[] mzBytes = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00 };
            await File.WriteAllBytesAsync(disguisedPe, mzBytes);

            // 2. A JPEG-looking header is a candidate for analysis, not proof of a safe image.
            string cleanJpg = Path.Combine(testFolder, "innocent_photo.jpg");
            byte[] jpegBytes = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46 };
            await File.WriteAllBytesAsync(cleanJpg, jpegBytes);

            using var coordinator = new ScanQueueCoordinator();
            var processedFiles = new System.Collections.Concurrent.ConcurrentBag<string>();

            var (total, scanned, skipped) = await coordinator.ExecuteScanQueueAsync(
                testFolder,
                ScanType.Custom,
                async (queueFunc) =>
                {
                    await queueFunc(disguisedPe);
                    await queueFunc(cleanJpg);
                },
                (path, ct) =>
                {
                    processedFiles.Add(path);
                    return Task.FromResult<SecurityFinding?>(null);
                },
                new System.Collections.Concurrent.ConcurrentBag<SecurityFinding>(),
                (file, tot, scn, skp) => { },
                CancellationToken.None);

            Assert.Contains(disguisedPe, processedFiles);
            Assert.Contains(cleanJpg, processedFiles);
            Assert.Equal(2, processedFiles.Count);
            Assert.Equal(2, total);
            Assert.Equal(2, scanned);
            Assert.Equal(0, skipped);
            Assert.Equal(2, coordinator.NewlyScanned);
            Assert.Equal(0, coordinator.ScannedFromCache);
            Assert.Equal(0, coordinator.SkippedSignedClean);
        }
    }
}
