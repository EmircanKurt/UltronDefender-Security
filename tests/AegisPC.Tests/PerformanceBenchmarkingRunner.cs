using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Scanning;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class PerformanceBenchmarkingRunner : IDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly string _benchDir;
        private readonly FileScannerService _scanner;

        public PerformanceBenchmarkingRunner(ITestOutputHelper output)
        {
            _output = output;
            _benchDir = Path.Combine(Path.GetTempPath(), "AegisPerfBench_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_benchDir);

            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskEngine = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var detectionHub = DetectionHubFactory.CreateDefault(hashService, sigVerifier);

            _scanner = new FileScannerService(
                hashService,
                sigVerifier,
                riskEngine,
                allowlist,
                findingService,
                detectionHub);
        }

        public void Dispose()
        {
            try { if (Directory.Exists(_benchDir)) Directory.Delete(_benchDir, recursive: true); } catch { }
        }

        [Fact]
        public async Task Test_Measure_P50_P95_P99_ScanLatency()
        {
            var latencies = new List<double>();
            var proc = Process.GetCurrentProcess();

            for (int i = 0; i < 50; i++)
            {
                string sampleFile = Path.Combine(_benchDir, $"sample_{i}.exe");
                await File.WriteAllTextAsync(sampleFile, "MZ" + new string('A', 1024 * 10)); // 10KB sample

                var sw = Stopwatch.StartNew();
                var result = await _scanner.ScanFileAsync(sampleFile);
                sw.Stop();

                latencies.Add(sw.Elapsed.TotalMilliseconds);
            }

            latencies.Sort();
            double p50 = latencies[(int)(latencies.Count * 0.50)];
            double p95 = latencies[(int)(latencies.Count * 0.95)];
            double p99 = latencies[(int)(latencies.Count * 0.99)];
            long memMb = proc.WorkingSet64 / (1024 * 1024);

            _output.WriteLine($"[PERFORMANCE BENCHMARK]");
            _output.WriteLine($"Throughput Samples: {latencies.Count} files");
            _output.WriteLine($"Scan Latency P50:   {p50:F2} ms");
            _output.WriteLine($"Scan Latency P95:   {p95:F2} ms");
            _output.WriteLine($"Scan Latency P99:   {p99:F2} ms");
            _output.WriteLine($"RAM WorkingSet:     {memMb} MB");

            Assert.True(p50 < 100.0, "P50 latency too high");
            Assert.True(p95 < 250.0, "P95 latency too high");
        }

        [Fact]
        public async Task Test_HardwareInfoService_Motherboard_RegistryFallback_NoUnknownString()
        {
            var hwService = new AegisPC.Performance.Hardware.HardwareInfoService();
            var profile = await hwService.GetHardwareProfileAsync();

            Assert.NotNull(profile);
            Assert.NotNull(profile.Motherboard);
            // Must not return dummy "Bilinmiyor Bilinmiyor"
            string summary = $"{profile.Motherboard.Manufacturer} {profile.Motherboard.Product}".Trim();
            Assert.DoesNotContain("Bilinmiyor Bilinmiyor", summary);

            if (profile.Motherboard.IsValid)
            {
                Assert.False(string.IsNullOrWhiteSpace(profile.Motherboard.Manufacturer));
                Assert.False(string.IsNullOrWhiteSpace(profile.Motherboard.Product));
            }
        }

        [Fact]
        public void Test_PerformanceMonitoring_Lifecycle_StopsTelemetry()
        {
            var vm = new AegisPC.App.ViewModels.PerformanceViewModel();

            // Default state
            Assert.Equal("En Çok İşlemci (CPU) Kullanan Süreçler", vm.ActiveTabTitle);

            // Tab selection
            vm.SelectProcessTab("1");
            Assert.Equal(1, vm.SelectedProcessTab);
            Assert.Equal("En Çok Bellek (RAM) Kullanan Süreçler", vm.ActiveTabTitle);

            vm.SelectProcessTab("2");
            Assert.Equal(2, vm.SelectedProcessTab);
            Assert.Equal("En Çok Grafik İşlemcisi (GPU) Kullanan Süreçler", vm.ActiveTabTitle);

            // Start & Stop lifecycle
            vm.StartLiveMonitoring();
            vm.StopLiveMonitoring();

            // Disposing should be safe and idempotent
            vm.Dispose();
            vm.Dispose();
        }

        [Fact]
        public async Task Test_10kFilesTree_SignedPassCache_SkipsHashComputation_OnSecondScan()
        {
            string treeDir = Path.Combine(_benchDir, "Tree10k_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(treeDir);

            const int folderCount = 100;
            const int filesPerFolder = 100;
            const int totalFiles = folderCount * filesPerFolder; // 10,000 files

            byte[] dummyBytes = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00 };

            try
            {
                // 10,000 dosyayı paralel oluştur
                Parallel.For(0, folderCount, i =>
                {
                    string sub = Path.Combine(treeDir, $"Folder_{i:D3}");
                    Directory.CreateDirectory(sub);
                    for (int j = 0; j < filesPerFolder; j++)
                    {
                        string filePath = Path.Combine(sub, $"file_{j:D3}.dll");
                        File.WriteAllBytes(filePath, dummyBytes);
                    }
                });

                var countingHash = new CountingHashService(new HashService());
                var sigVerifier = new SignatureVerifier();
                var riskEngine = new RiskScoringEngine();
                var allowlist = new AllowlistService(countingHash);
                var findingService = new SecurityFindingService();
                var detectionHub = DetectionHubFactory.CreateDefault(countingHash, sigVerifier);

                var scanner = new FileScannerService(
                    countingHash,
                    sigVerifier,
                    riskEngine,
                    allowlist,
                    findingService,
                    detectionHub);

                // Tarama 1: İlk geçiş (Cold scan)
                var sw1 = Stopwatch.StartNew();
                var result1 = await scanner.ScanDirectoryAsync(treeDir, ScanType.Custom);
                sw1.Stop();
                int scan1HashCalls = countingHash.ComputeCount;

                // Hash sayacını sıfırla
                countingHash.ResetCount();

                // Tarama 2: İkinci geçiş (Warm scan - önbellek devrede)
                var sw2 = Stopwatch.StartNew();
                var result2 = await scanner.ScanDirectoryAsync(treeDir, ScanType.Custom);
                sw2.Stop();
                int scan2HashCalls = countingHash.ComputeCount;

                double skipRatio = 1.0 - ((double)scan2HashCalls / totalFiles);
                double speedup = (double)sw1.ElapsedMilliseconds / Math.Max(1, sw2.ElapsedMilliseconds);

                _output.WriteLine($"[10K TREE BENCHMARK RESULTS]");
                _output.WriteLine($"Toplam Dosya Sayısı:    {totalFiles:N0}");
                _output.WriteLine($"1. Tarama Süresi:       {sw1.ElapsedMilliseconds} ms (Hash Çağrısı: {scan1HashCalls})");
                _output.WriteLine($"2. Tarama Süresi:       {sw2.ElapsedMilliseconds} ms (Hash Çağrısı: {scan2HashCalls})");
                _output.WriteLine($"Hash Atlanma Oranı:     {skipRatio:P2}");
                _output.WriteLine($"Hızlanma Faktörü:       {speedup:F2}x");

                Assert.Equal(totalFiles, result1.ScannedFiles);
                Assert.Equal(totalFiles, result2.ScannedFiles);
                // 2. taramada en az %80 hash atlanması garanti edilmeli
                Assert.True(skipRatio >= 0.80, $"2. taramada hash atlanma oranı >= %80 olmalıdır. Elde edilen: {skipRatio:P2}");
                Assert.True(sw2.ElapsedMilliseconds <= sw1.ElapsedMilliseconds * 1.5, "2. tarama ilkinden daha hızlı veya benzer olmalıdır.");
            }
            finally
            {
                try
                {
                    if (Directory.Exists(treeDir))
                    {
                        Directory.Delete(treeDir, true);
                    }
                }
                catch { }
            }
        }
    }

    public class CountingHashService : IHashService
    {
        private readonly IHashService _inner;
        private int _computeCount;

        public CountingHashService(IHashService inner) => _inner = inner;
        public int ComputeCount => _computeCount;
        public void ResetCount() => Volatile.Write(ref _computeCount, 0);

        public Task<string> ComputeSha256Async(string filePath, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _computeCount);
            return _inner.ComputeSha256Async(filePath, cancellationToken);
        }

        public Task<string> ComputeSha1Async(string filePath, CancellationToken cancellationToken = default)
        {
            return _inner.ComputeSha1Async(filePath, cancellationToken);
        }
    }
}
