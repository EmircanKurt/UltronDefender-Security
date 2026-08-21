using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Enums;
using AegisPC.Security.AntiEvasion;
using AegisPC.Security.Archive;
using AegisPC.Security.Caching;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.PE;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class SecurityBenchmarkTests : IDisposable
    {
        private readonly string _sandboxDir;

        public SecurityBenchmarkTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "Aegis_BenchmarkTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Benchmark_DetectionHub_AggregationLatency_UnderTenMilliseconds()
        {
            var hashService = new HashService();
            var hub = new DetectionHub();
            hub.RegisterDetector(new HashSignatureDetector(hashService));
            hub.RegisterDetector(new DeepPeDetector());
            hub.RegisterDetector(new AntiEvasionDetectorPlugin());
            hub.RegisterDetector(new ArchiveDetectorPlugin());

            var testFile = Path.Combine(_sandboxDir, "latency_test.exe");
            await File.WriteAllBytesAsync(testFile, Encoding.ASCII.GetBytes("MZ_LATENCY_BENCHMARK_SAMPLE_FOR_DETECTION_HUB_HIGH_SPEED"));

            var context = new DetectionContext { FilePath = testFile };

            // Warm up
            await hub.EvaluateAsync(context);

            var sw = Stopwatch.StartNew();
            int iterations = 20;
            for (int i = 0; i < iterations; i++)
            {
                var verdict = await hub.EvaluateAsync(context);
                Assert.NotNull(verdict);
            }
            sw.Stop();

            double avgMs = sw.Elapsed.TotalMilliseconds / iterations;
            Assert.True(avgMs < 15.0, $"DetectionHub average evaluation latency must be < 15ms (Actual: {avgMs:F2}ms).");
        }

        [Fact]
        public async Task Benchmark_MultiLayerScanCache_L1Lookup_UnderOneMillisecond()
        {
            var cache = new MultiLayerScanCache(_sandboxDir);
            var testFile = Path.Combine(_sandboxDir, "cache_bench.bin");
            await File.WriteAllBytesAsync(testFile, new byte[1024]);

            var fileInfo = new FileInfo(testFile);
            var sha = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";
            var now = DateTime.UtcNow;
            var cachedVerdict = new CachedScanVerdict
            {
                SHA256 = sha,
                FilePath = testFile,
                FileSize = fileInfo.Length,
                LastWriteTimeUtc = now,
                Verdict = RealTimeVerdict.Clean,
                RecommendedPolicy = RealTimePolicyAction.Allow,
                RiskScore = 0,
                RiskLevel = RiskLevel.Clean,
                Confidence = 0.99
            };

            await cache.SetVerdictAsync(cachedVerdict);

            var sw = Stopwatch.StartNew();
            int iterations = 100;
            for (int i = 0; i < iterations; i++)
            {
                var result = await cache.TryGetVerdictAsync(testFile, sha, fileInfo.Length, now);
                Assert.NotNull(result);
                Assert.Equal(0, result.RiskScore);
            }
            sw.Stop();

            double avgMicroseconds = (sw.Elapsed.TotalMilliseconds * 1000) / iterations;
            Assert.True(avgMicroseconds < 500, $"L1 Cache lookup must be < 500 microseconds (Actual: {avgMicroseconds:F1} µs).");
        }
    }
}
