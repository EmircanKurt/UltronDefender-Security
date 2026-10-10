using System.Diagnostics;
using System.IO;
using AegisPC.Core.Enums;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests;

/// <summary>Exercises real content/hash/detector inspection on scoped inert inputs and our own assemblies, with no execution or actions.</summary>
public sealed class FlatRouteBenignPipelineReviewTests(ITestOutputHelper output)
{
    /// <summary>Compares five identical hash-only workloads before/after bounded scheduling, not full antivirus or cold-disk speed.</summary>
    [Fact]
    public async Task FiveRuns_BoundedSchedulingChangesFirstCompletionWithoutOmittingBytes()
    {
        using var fixture = ReviewStageOneFixture.Create();
        var large = new FileInfo(fixture.WriteInput("large.txt", new byte[32 * 1024 * 1024]));
        var small = new FileInfo(fixture.WriteInput("small.exe", System.Text.Encoding.UTF8.GetBytes("inert benign text")));
        var source = new[] { large, small };
        var identities = new Dictionary<string, string>();
        foreach (var file in source) identities[file.FullName] = await fixture.ComputeInputIdentityAsync(file.FullName);
        using var process = Process.GetCurrentProcess();
        for (int repeat = 0; repeat < 5; repeat++)
        {
            foreach (bool scheduled in repeat % 2 == 0 ? new[] { false, true } : new[] { true, false })
            {
                var files = scheduled ? StartupCandidateScheduling.Order(source, default).ToArray() : source;
                Assert.Equal(scheduled ? small.FullName : large.FullName, files[0].FullName);
                process.Refresh(); long ramBefore = process.WorkingSet64; var cpu = process.TotalProcessorTime;
                var clock = Stopwatch.StartNew(); double firstCompletionMs = 0; long bytes = 0;
                for (int i = 0; i < files.Length; i++)
                {
                    Assert.Equal(identities[files[i].FullName], await fixture.HashService.ComputeSha256Async(files[i].FullName), ignoreCase: true);
                    bytes += files[i].Length; if (i == 0) firstCompletionMs = clock.Elapsed.TotalMilliseconds;
                }
                clock.Stop(); process.Refresh(); Assert.Equal(large.Length + small.Length, bytes);
                output.WriteLine($"repeat={repeat+1} scheduled={scheduled} files={files.Length} bytes={bytes} first_ms={firstCompletionMs:F2} total_ms={clock.Elapsed.TotalMilliseconds:F2} cpu_ms={(process.TotalProcessorTime-cpu).TotalMilliseconds:F2} ram_before={ramBefore} ram_after={process.WorkingSet64}");
            }
        }
    }

    /// <summary>Five warm runs must retain exact content identity and not classify ordinary input or Ultron assemblies as confirmed malware.</summary>
    [Fact]
    public async Task FiveRuns_CommonInspectionRetainsIdentityAndDoesNotFlagSelf()
    {
        using var fixture = ReviewStageOneFixture.Create();
        byte[] opaque = new byte[4 * 1024 * 1024]; new Random(9182).NextBytes(opaque);
        var paths = new[]
        {
            fixture.WriteInput("ordinary.txt", System.Text.Encoding.UTF8.GetBytes("Ordinary harmless review document.")),
            fixture.WriteInput("opaque.bin", opaque),
            fixture.ImportReadOnlyInput(typeof(AegisPC.App.ViewModels.ScanViewModel).Assembly.Location, "ultron-app.dll"),
            fixture.ImportReadOnlyInput(typeof(HashService).Assembly.Location, "ultron-security.dll")
        };
        var identities = new Dictionary<string, string>();
        foreach (string path in paths) identities[path] = await fixture.ComputeInputIdentityAsync(path);
        var processor = new RealTimeVerdictProcessor(fixture.HashService, fixture.SignatureVerifier,
            new RiskScoringEngine(), null, null, exclusionService: null, detectionHub: fixture.CreateHub());
        using var process = Process.GetCurrentProcess();
        for (int repeat = 0; repeat < 5; repeat++)
        {
            var clock = Stopwatch.StartNew(); var cpu = process.TotalProcessorTime;
            foreach (string path in paths)
            {
                using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                var verdict = await processor.InspectFileAsync(path, budget.Token).WaitAsync(TimeSpan.FromSeconds(20));
                Assert.Equal(identities[path], verdict.SHA256, ignoreCase: true);
                Assert.NotEqual(RealTimeVerdict.ConfirmedMalicious, verdict.Verdict);
                Assert.NotEqual(RealTimePolicyAction.BlockAndQuarantine, verdict.RecommendedPolicy);
                Assert.InRange(verdict.RiskScore, 0, 49);
                output.WriteLine($"repeat={repeat+1} fixture={Path.GetFileName(path)} verdict={verdict.Verdict} score={verdict.RiskScore} complete={verdict.InspectionComplete} gaps={string.Join(';',verdict.CoverageLimitations)}");
            }
            clock.Stop(); process.Refresh();
            output.WriteLine($"repeat={repeat+1} files={paths.Length} elapsed_ms={clock.Elapsed.TotalMilliseconds:F2} cpu_ms={(process.TotalProcessorTime-cpu).TotalMilliseconds:F2} working_set_bytes={process.WorkingSet64}");
        }
        foreach (string path in paths) Assert.Equal(identities[path], await fixture.ComputeInputIdentityAsync(path));
    }

    /// <summary>Five benign copied-OS-file runs exercise the common detector pipeline with inert providers, not real malware/AMSI efficacy.</summary>
    [Theory]
    [InlineData("win32u.dll")]
    [InlineData("WS2_32.dll")]
    [InlineData("cryptbase.dll")]
    [InlineData("shlwapi.dll")]
    public async Task FiveRuns_WindowsDllCommonPipeline_NoFalseWarning(string fileName)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.ImportReadOnlyInput(Path.Combine(Environment.SystemDirectory, fileName), fileName);
        string hash = await fixture.ComputeInputIdentityAsync(path);
        var processor = new RealTimeVerdictProcessor(fixture.HashService, fixture.SignatureVerifier,
            new RiskScoringEngine(), null, null, exclusionService: null, detectionHub: fixture.CreateHub());
        using var process = Process.GetCurrentProcess();
        for (int run = 1; run <= 5; run++)
        {
            var cpu = process.TotalProcessorTime;
            var timer = Stopwatch.StartNew();
            using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var verdict = await processor.InspectFileAsync(path, budget.Token).WaitAsync(TimeSpan.FromSeconds(20));
            timer.Stop(); process.Refresh();
            output.WriteLine($"file={fileName} run={run} score={verdict.RiskScore} verdict={verdict.Verdict} ms={timer.Elapsed.TotalMilliseconds:F2} cpu_ms={(process.TotalProcessorTime-cpu).TotalMilliseconds:F2} ram_bytes={process.WorkingSet64} gaps={string.Join(';',verdict.CoverageLimitations)}");
            Assert.Equal(hash, verdict.SHA256, ignoreCase: true);
            Assert.InRange(verdict.RiskScore, 0, 49);
            Assert.NotEqual(RealTimePolicyAction.BlockAndQuarantine, verdict.RecommendedPolicy);
        }
    }
}
