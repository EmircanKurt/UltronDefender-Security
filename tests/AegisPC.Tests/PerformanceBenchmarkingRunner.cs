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
    }
}
