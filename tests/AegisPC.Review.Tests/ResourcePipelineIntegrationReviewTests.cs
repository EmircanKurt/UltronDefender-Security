using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Security.Detection;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests;

/// <summary>Explicitly opted-in benign local integration; no actions, native watchers, upload or fixture execution.</summary>
public sealed partial class StartupSweepSafetyTests
{
    private readonly ITestOutputHelper _resourceOutput;
    /// <summary>Captures reproducible measurements; xUnit provides one output sink per fixture.</summary>
    public StartupSweepSafetyTests(ITestOutputHelper output) => _resourceOutput = output;

    [Fact]
    public async Task LocalBenignPipeline_FiveRuns_OneVersusFourWorkers_WhenProvided()
    {
        string fixture = Environment.GetEnvironmentVariable("ULTRON_BENIGN_SCAN_FIXTURE")
            ?? throw new InvalidOperationException("Run this opted-in integration only with an explicitly provided benign fixture.");
        Assert.True(File.Exists(fixture));
        var workspace = new DirectoryInfo(AppContext.BaseDirectory);
        while (workspace != null && !File.Exists(Path.Combine(workspace.FullName, "AegisPC.sln"))) workspace = workspace.Parent;
        Assert.NotNull(workspace);
        var root = workspace!.FullName;
        string[] paths = [Path.GetFullPath(fixture),
            Path.Combine(root, "AegisPC_App", "UltronDefender.exe"),
            Path.Combine(root, "src", "AegisPC.App", "bin", "Release", "net8.0-windows", "UltronDefender.dll"),
            Path.Combine(root, "src", "AegisPC.Security", "bin", "Release", "net8.0-windows", "AegisPC.Security.dll")];
        var hashes = paths.ToDictionary(p => p, p => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p))));
        var serial = new List<double>();
        var parallel = new List<double>();
        var before = new Dictionary<string, (RealTimeVerdict Verdict, int Score, bool Complete)>();
        using var process = Process.GetCurrentProcess();
        for (int run = 0; run < 5; run++)
        {
            // Alternate order to expose warm-cache/order bias. This is not a cold-cache hardware certification.
            foreach (int workers in run % 2 == 0 ? new[] { 1, 4 } : new[] { 4, 1 })
            {
                var hash = new HashService();
                var verifier = new SignatureVerifier();
                var hub = DetectionHubFactory.CreateDefault(hashService: hash, signatureVerifier: verifier);
                var processor = new RealTimeVerdictProcessor(hash, verifier, new RiskScoringEngine(), null, null,
                    exclusionService: null, detectionHub: hub);
                var engine = new RecordingEngine(_ => throw new InvalidOperationException("Only actual common inspection is permitted."))
                {
                    AsyncInspect = async (path, token) =>
                    {
                        var verdict = await processor.InspectFileAsync(path, token);
                        _resourceOutput.WriteLine($"inspected={Path.GetFileName(path)} verdict={verdict.Verdict} score={verdict.RiskScore} evidence={string.Join(';', verdict.Evidences)}");
                        Assert.Equal(hashes[path], verdict.SHA256, ignoreCase: true);
                        Assert.InRange(verdict.RiskScore, 0, 49);
                        Assert.NotEqual(RealTimeVerdict.ConfirmedMalicious, verdict.Verdict);
                        var identity = (verdict.Verdict, verdict.RiskScore, verdict.InspectionComplete);
                        lock (before)
                        {
                            if (before.TryGetValue(path, out var prior)) Assert.Equal(prior, identity);
                            else before[path] = identity;
                        }
                        _resourceOutput.WriteLine($"file={Path.GetFileName(path)} verdict={verdict.Verdict} score={verdict.RiskScore} complete={verdict.InspectionComplete}");
                        return verdict;
                    }
                };
                var coordinator = new RecordingCoordinator();
                var vault = new RecordingVault();
                var sweep = new StartupSecuritySweepService(engine, vault, scanCoordinator: coordinator,
                    resourceManagerFactory: () => new FixedResources(workers), storageClassifier: _ => true);
                using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                var cpu = process.TotalProcessorTime;
                var clock = Stopwatch.StartNew();
                var result = await sweep.RunSweepAsync(paths, limit.Token);
                double elapsed = clock.Elapsed.TotalMilliseconds;
                (workers == 1 ? serial : parallel).Add(elapsed);
                Assert.Equal(4, result.TotalScanned);
                Assert.NotEqual(StartupSweepStatus.Failed, result.FinalStatus);
                Assert.Empty(coordinator.LastResult!.Findings);
                Assert.NotNull(coordinator.LastResult.Measurements);
                Assert.Equal(4, coordinator.LastResult.Measurements.Volumes.Sum(v => v.FinishedAttempts));
                Assert.All(coordinator.LastResult.Measurements.Volumes, v => Assert.InRange(v.PeakActiveWorkers, 1, workers));
                Assert.Equal(0, vault.BoundCalls);
                process.Refresh();
                _resourceOutput.WriteLine($"run={run + 1} workers={workers} elapsed_ms={elapsed:F2} cpu_ms={(process.TotalProcessorTime - cpu).TotalMilliseconds:F2} rss_mb={process.WorkingSet64 / 1048576.0:F1} peak_mb={process.PeakWorkingSet64 / 1048576.0:F1} files={result.TotalScanned} incomplete={result.IncompleteCount} timeouts={result.TimedOutCount}");
            }
        }
        double first = serial.Order().ElementAt(2), second = parallel.Order().ElementAt(2);
        _resourceOutput.WriteLine($"single_median_ms={first:F2} parallel_median_ms={second:F2} gain_percent={(first - second) * 100 / first:F2}");
        foreach (string path in paths) Assert.Equal(hashes[path], Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))));
    }
}
