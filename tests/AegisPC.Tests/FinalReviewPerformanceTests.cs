using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Security.Scanning;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests;

/// <summary>Measures benign real-file scan throughput; not a malware efficacy or low-end hardware certification.</summary>
[Collection("SequentialDiskTests")]
public sealed class FinalReviewPerformanceTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "Aegis_FinalPerf_" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task ResourceModes_CompleteBenignFiles_WithMeasuredCpuMemoryAndCache()
    {
        Directory.CreateDirectory(_root);
        using var process = Process.GetCurrentProcess();
        foreach (var mode in new[] { ScanResourceMode.VeryLow, ScanResourceMode.Balanced, ScanResourceMode.Auto, ScanResourceMode.Maximum })
        {
            string directory = Path.Combine(_root, mode.ToString());
            Directory.CreateDirectory(directory);
            foreach (int i in Enumerable.Range(0, 80))
                await File.WriteAllTextAsync(Path.Combine(directory, $"benign_{i}.dat"), new string('B', 16384));
            using var manager = new AdaptiveScanResourceManager(directory);
            manager.SetMode(mode);
            var hash = new HashService();
            var scanner = new FileScannerService(hash, new SignatureVerifier(), new RiskScoringEngine(),
                new AllowlistService(hash), resourceManager: manager);
            process.Refresh();
            TimeSpan cpuStart = process.TotalProcessorTime;
            long allocatedStart = GC.GetTotalAllocatedBytes();
            int gcStart = GC.CollectionCount(2);
            var clock = Stopwatch.StartNew();
            var first = await scanner.ScanDirectoryAsync(directory, ScanType.Custom);
            double seconds = clock.Elapsed.TotalSeconds;
            process.Refresh();
            output.WriteLine($"{mode}: files={first.ScannedFiles}, failures={first.FailedFiles}, timeMs={seconds * 1000:F0}, filesPerSec={first.ScannedFiles / seconds:F1}, cpuMs={(process.TotalProcessorTime - cpuStart).TotalMilliseconds:F0}, workingSetMiB={process.WorkingSet64 / 1048576.0:F1}, allocatedMiB={(GC.GetTotalAllocatedBytes() - allocatedStart) / 1048576.0:F1}, gen2={GC.CollectionCount(2) - gcStart}, workers={manager.ActiveProfile.Concurrency}, advisoryBudgetMiB={manager.ActiveProfile.MaxMemoryBudgetBytes / 1048576}");
            Assert.Equal(80, first.ScannedFiles);
            Assert.Equal(0, first.FailedFiles);
            Assert.Equal(0, first.TimedOutFiles);
            Assert.Empty(first.Findings);
            clock.Restart();
            var cached = await scanner.ScanDirectoryAsync(directory, ScanType.Custom);
            output.WriteLine($"{mode} content-verified repeated scan: timeMs={clock.Elapsed.TotalMilliseconds:F0}, files={cached.ScannedFiles}, cacheHits={scanner.HashMatcher.ScannedFromCache}");
            Assert.Equal(80, cached.ScannedFiles);
            Assert.Equal(80, scanner.HashMatcher.ScannedFromCache);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
