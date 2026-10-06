using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using AegisPC.Security.Scanning;
using AegisPC.Security.Detection;
using AegisPC.Security.RealTime;
using AegisPC.Core.Enums;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests;

/// <summary>Exercises the actual streaming matcher with inert bytes, not malware or host protection actions.</summary>
public sealed class ContentSearchStallReviewTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "UltronContentSearch_" + Guid.NewGuid().ToString("N"));

    /// <summary>ASCII and UTF-16LE indicators survive case changes, unaligned placement, chunk boundaries and a late position.</summary>
    [Theory]
    [InlineData(false, 262139)]
    [InlineData(true, 262130)]
    [InlineData(true, 262131)]
    [InlineData(true, 262145)]
    [InlineData(false, 7340019)]
    [InlineData(true, 7340019)]
    public async Task IndicatorsAcrossWholeFile_AreNotLost(bool wide, int position)
    {
        var data = new byte[8 * 1024 * 1024];
        byte[] token = (wide ? Encoding.Unicode : Encoding.ASCII).GetBytes("gEtAsYnCkEyStAtE");
        token.CopyTo(data, position);
        string path = CreateFile(data);
        var (pattern, apis) = await MalwareSignatureDatabase.CheckFileContentAndApisAsync(path);
        Assert.False(pattern.IsMatched);
        Assert.Contains(apis, x => x.ApiName == "GetAsyncKeyState");
        Assert.Single(apis);
    }

    /// <summary>Missing, truncated or non-ASCII high-byte tokens do not accidentally become API evidence.</summary>
    [Theory]
    [InlineData("GetAsyncKeyStat")]
    [InlineData("getasync-key-state")]
    [InlineData("ordinary benign binary documentation")]
    public async Task IncompleteToken_IsNotApiEvidence(string text)
    {
        var (_, apis) = await MalwareSignatureDatabase.CheckFileContentAndApisAsync(CreateFile(Encoding.UTF8.GetBytes(text)));
        Assert.Empty(apis);
    }

    /// <summary>Cancellation interrupts real streaming work instead of returning an incomplete clean result.</summary>
    [Fact]
    public async Task CancellationDuringLargeRead_PropagatesPromptly()
    {
        string path = CreateFile(new byte[32 * 1024 * 1024]);
        using var cancellation = new CancellationTokenSource();
        cancellation.CancelAfter(TimeSpan.FromMilliseconds(5));
        var watch = Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            MalwareSignatureDatabase.CheckFileContentAndApisAsync(path, cancellation.Token));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5));
    }

    /// <summary>Comparative five-run microbenchmark loads the exact pre-fix binary in an isolated context; timings are not antivirus efficacy.</summary>
    [Fact]
    public async Task FiveRuns_SameBenignCoverage_ReportBeforeAfter()
    {
        string workspace = FindWorkspace();
        string legacyPath = Path.Combine(workspace, "artifacts", "ui-checkpoints", "scan-stall-before-2026-10-06", "portable", "AegisPC.Security.dll");
        if (!File.Exists(legacyPath)) { output.WriteLine("Comparative artifact not present; benchmark not run."); return; }
        var load = new AssemblyLoadContext("UltronPreFixBenchmark", isCollectible: true);
        load.Resolving += (_, name) => AssemblyLoadContext.Default.Assemblies.FirstOrDefault(a => a.GetName().Name == name.Name);
        var data = new byte[256 * 1024];
        new Random(2817).NextBytes(data);
        string path = CreateFile(data);
        try
        {
            var type = load.LoadFromAssemblyPath(legacyPath).GetType(typeof(MalwareSignatureDatabase).FullName!)!;
            var method = type.GetMethod(nameof(MalwareSignatureDatabase.CheckFileContentAndApisAsync))!;
            using var process = Process.GetCurrentProcess();
            var before = new List<double>();
            var after = new List<double>();
            for (int run = 0; run < 5; run++)
            {
                var cpu = process.TotalProcessorTime;
                var watch = Stopwatch.StartNew();
                var legacy = (Task)method.Invoke(null, [path, CancellationToken.None])!;
                await legacy.WaitAsync(TimeSpan.FromSeconds(60));
                before.Add(watch.Elapsed.TotalMilliseconds);
                var tuple = legacy.GetType().GetProperty("Result")!.GetValue(legacy)!;
                var oldApis = (List<(string ApiName, int Weight, string Description)>)tuple.GetType().GetField("Item2")!.GetValue(tuple)!;
                output.WriteLine($"run={run + 1} before_ms={before[^1]:F2} before_cpu_ms={(process.TotalProcessorTime - cpu).TotalMilliseconds:F2} working_set_mb={process.WorkingSet64 / 1048576.0:F1}");
                cpu = process.TotalProcessorTime;
                watch.Restart();
                var (_, newApis) = await MalwareSignatureDatabase.CheckFileContentAndApisAsync(path);
                after.Add(watch.Elapsed.TotalMilliseconds);
                Assert.Equal(oldApis.Select(x => x.ApiName), newApis.Select(x => x.ApiName));
                output.WriteLine($"run={run + 1} after_ms={after[^1]:F2} after_cpu_ms={(process.TotalProcessorTime - cpu).TotalMilliseconds:F2} working_set_mb={process.WorkingSet64 / 1048576.0:F1}");
            }
            output.WriteLine($"same_bytes={data.Length} before_median_ms={before.Order().ElementAt(2):F2} after_median_ms={after.Order().ElementAt(2):F2}");
        }
        finally { load.Unload(); }
    }

    private string CreateFile(byte[] data)
    {
        Directory.CreateDirectory(_root);
        string path = Path.Combine(_root, Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, data);
        return path;
    }

    /// <summary>Optional local integration probe inspects an explicitly provided benign fixture without actions, uploads or starting watchers.</summary>
    [Fact]
    public async Task SharedPipeline_BenignInstallerProbe_WhenProvided()
    {
        string? fixture = Environment.GetEnvironmentVariable("ULTRON_BENIGN_SCAN_FIXTURE");
        if (string.IsNullOrEmpty(fixture)) { output.WriteLine("Optional local fixture not provided; integration probe not run."); return; }
        Assert.True(File.Exists(fixture));
        string originalHash;
        await using (var file = File.OpenRead(fixture)) originalHash = Convert.ToHexString(await SHA256.HashDataAsync(file));
        var verifier = new SignatureVerifier();
        var signature = await verifier.VerifySignatureAsync(fixture);
        Assert.True(signature.IsValid);
        using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(fixture));
        Assert.Contains("O=Microsoft Corporation", certificate.Subject);
        var hash = new HashService();
        var hub = DetectionHubFactory.CreateDefault(hashService: hash, signatureVerifier: verifier);
        var processor = new RealTimeVerdictProcessor(hash, verifier, new RiskScoringEngine(), null, null,
            exclusionService: null, detectionHub: hub);
        var scanner = new FileScannerService(hash, verifier, new NoAllowlist(), hub);
        for (int run = 0; run < 5; run++)
        {
            using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var watch = Stopwatch.StartNew();
            var verdict = await processor.InspectFileAsync(fixture, budget.Token);
            Assert.Equal(originalHash, verdict.SHA256, ignoreCase: true);
            Assert.NotEqual(RealTimeVerdict.ConfirmedMalicious, verdict.Verdict);
            Assert.NotEqual(RealTimePolicyAction.BlockAndQuarantine, verdict.RecommendedPolicy);
            Assert.InRange(verdict.RiskScore, 0, 49);
            output.WriteLine($"installer_run={run + 1} bytes={new FileInfo(fixture).Length} elapsed_ms={watch.Elapsed.TotalMilliseconds:F2} verdict={verdict.Verdict} score={verdict.RiskScore} complete={verdict.InspectionComplete} limitations={string.Join(';', verdict.CoverageLimitations)}");
            watch.Restart();
            var manual = await scanner.ScanDirectoryAsync(fixture, ScanType.Custom, cancellationToken: budget.Token);
            Assert.Equal(ScanStatus.Completed, manual.Status);
            Assert.Equal(1, manual.TotalFiles);
            Assert.Equal(1, manual.ScannedFiles);
            Assert.DoesNotContain(manual.Findings, f => f.RiskLevel == RiskLevel.ConfirmedMalicious);
            Assert.Empty(manual.Findings);
            Assert.False(manual.Coverage.IsComplete);
            Assert.Equal(1, manual.FailedFiles);
            output.WriteLine($"manual_run={run + 1} elapsed_ms={watch.Elapsed.TotalMilliseconds:F2} status={manual.Status} scanned={manual.ScannedFiles} incomplete={manual.FailedFiles} timeouts={manual.TimedOutFiles}");
        }
        await using (var file = File.OpenRead(fixture)) Assert.Equal(originalHash, Convert.ToHexString(await SHA256.HashDataAsync(file)));
    }

    private static string FindWorkspace()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "AegisPC.sln"))) dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("Review workspace not found.");
    }

    private sealed class NoAllowlist : IAllowlistService
    {
        public bool IsAllowlisted(string sha256) => false;
        public bool IsPathAllowlisted(string path) => false;
        public Task<bool> IsAllowlistedAsync(string sha256, CancellationToken ct = default) => Task.FromResult(false);
        public Task<bool> IsPathAllowlistedAsync(string path, CancellationToken ct = default) => Task.FromResult(false);
        public Task AddToAllowlistAsync(AllowlistEntry entry, CancellationToken ct = default) => throw new InvalidOperationException("Read-only fixture.");
        public Task RemoveFromAllowlistAsync(int id, CancellationToken ct = default) => throw new InvalidOperationException("Read-only fixture.");
        public Task<List<AllowlistEntry>> GetAllowlistAsync(CancellationToken ct = default) => Task.FromResult(new List<AllowlistEntry>());
        public Task<bool> CheckHashChangedAsync(AllowlistEntry entry, CancellationToken ct = default) => Task.FromResult(true);
    }

    /// <summary>Removes only this test's verified unique temporary directory.</summary>
    public void Dispose()
    {
        string full = Path.GetFullPath(_root);
        if (full.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) && Directory.Exists(full))
            Directory.Delete(full, recursive: true);
    }
}
