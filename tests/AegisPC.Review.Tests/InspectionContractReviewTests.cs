using System.IO;
using System.Reflection;
using System.Text;
using System.IO.Compression;
using AegisPC.Security.Archive;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Real temporary-file inspections with inert OS/provider/action boundaries; no malware or containment.</summary>
public sealed class InspectionContractReviewTests
{
    [Theory]
    [InlineData("amsiInitFailed", ".txt")]
    [InlineData("AmsiUtils", ".ps1")]
    [InlineData("VirtualAlloc", ".rar")]
    [InlineData("WriteProcessMemory", ".jpg")]
    [InlineData("CreateRemoteThread", "")]
    public async Task LiteralApiDocumentation_DoesNotBecomeAnAttack(string name, string extension)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("lesson" + extension, Encoding.UTF8.GetBytes(
            "This documentation explains the literal name " + name + ". No code is executed."));
        var result = await new DetectionHub(initialDetectors: [new ScriptHeuristicDetector()])
            .EvaluateAsync(new DetectionContext { FilePath = path, SHA256 = await fixture.ComputeInputIdentityAsync(path) });
        Assert.True(result.IsComplete);
        Assert.True(result.RiskScore <= 25, result.ScoreTrace);
        Assert.NotEqual(DetectionVerdict.Suspicious, result.Verdict);
        Assert.All(result.Evidences, evidence => Assert.Equal(EvidenceNature.Capability, evidence.Nature));
    }

    [Fact]
    public void UninitializedResults_DoNotClaimInspectionCompleted()
    {
        Assert.False(new RealTimeVerdictResult().InspectionComplete);
        Assert.False(new DetectionResult().IsComplete);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("empty")]
    [InlineData("excluded")]
    [InlineData("locked")]
    public async Task UninspectedFile_HasAnExplicitCoverageReason(string condition)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", condition == "empty" ? [] : Encoding.UTF8.GetBytes("An ordinary note."));
        if (condition == "missing") File.Delete(path);
        using var writer = condition == "locked" ? new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite) : null;
        var processor = new RealTimeVerdictProcessor(fixture.HashService, fixture.SignatureVerifier,
            new InertRisk(), null, null, new InertExclusions(condition == "excluded"), detectionHub: fixture.CreateHub());
        var result = await processor.InspectFileAsync(path);
        Assert.False(result.InspectionComplete);
        Assert.NotEmpty(result.CoverageLimitations);
        Assert.NotEqual(RealTimeVerdict.Clean, result.Verdict);
    }

    [Fact]
    public async Task HubExclusion_DoesNotCertifyUninspectedContent()
    {
        var hub = new DetectionHub(exclusionService: new InertExclusions(true));
        var result = await hub.EvaluateAsync(new DetectionContext { FilePath = "unused-fixture-path" });
        Assert.False(result.IsComplete);
        Assert.NotEmpty(result.CoverageLimitations);
        Assert.Equal(DetectionVerdict.Unknown, result.Verdict);
    }

    [Fact]
    public async Task CacheInvalidation_DoesNotAccumulateEvictionKeys()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("Cache bookkeeping fixture."));
        string hash = await fixture.ComputeInputIdentityAsync(path);
        var info = new FileInfo(path);
        var matcher = new FileHashMatcher(fixture.HashService, fixture.SignatureVerifier, new InertAllowlist());
        for (int i = 0; i < 100_000; i++)
        {
            matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, null, hash, false, false);
            matcher.InvalidateCache(path);
        }
        Assert.Equal(0, matcher.CachedEntriesCount);
        var bookkeeping = typeof(FileHashMatcher).GetField("_cacheKeyQueue", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(matcher)!;
        Assert.Equal(0, (int)bookkeeping.GetType().GetProperty("Count")!.GetValue(bookkeeping)!);
        matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, null, hash, false, false);
        Assert.True((await matcher.TryGetCachedAsync(path, info, CancellationToken.None)).Hit);
    }

    /// <summary>Real benign bytes reach common inspection regardless of a misleading container extension.</summary>
    [Theory]
    [InlineData(".rar")]
    [InlineData(".zip")]
    [InlineData(".jar")]
    [InlineData(".jpg")]
    public async Task HarmlessRenamedText_ManualAndRealtimeUseTheSameCoverage(string extension)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("ordinary" + extension, Encoding.UTF8.GetBytes("An ordinary local note with no commands."));
        using var resources = new InertResources();
        using var queue = new ScanQueueCoordinator(resources);
        var scanner = new FileScannerService(new DirectoryWalker(), queue,
            new FileHashMatcher(fixture.HashService, fixture.SignatureVerifier, new InertAllowlist()),
            new PupAnalysisCoordinator(fixture.CreateHub()), new ArchiveSafetyScanner());
        var manual = await scanner.ScanFileDetailedAsync(path, TimeSpan.FromSeconds(5));
        var processor = new RealTimeVerdictProcessor(fixture.HashService, fixture.SignatureVerifier,
            new InertRisk(), null, null, null, detectionHub: fixture.CreateHub());
        var realtime = await processor.InspectFileAsync(path);
        Assert.Equal(FileScanOutcome.Success, manual.Outcome);
        Assert.True(manual.InspectionComplete);
        Assert.Null(manual.Finding);
        Assert.True(realtime.InspectionComplete);
        Assert.Equal(RealTimeVerdict.Clean, realtime.Verdict);
    }

    /// <summary>Synthetic member evidence in a real benign ZIP retains each member identity; no malware/action is used.</summary>
    [Fact]
    public async Task ArchiveEvidence_DoesNotCollapseDistinctMembersOnTheOuterPath()
    {
        using var fixture = ReviewStageOneFixture.Create();
        using var bytes = new MemoryStream();
        using (var zip = new ZipArchive(bytes, ZipArchiveMode.Create, leaveOpen: true))
            foreach (string member in new[] { "one.txt", "two.txt" })
            {
                using var writer = new StreamWriter(zip.CreateEntry(member).Open());
                writer.Write("Ordinary archive contract fixture.");
            }
        string path = fixture.WriteInput("container.bin", bytes.ToArray());
        string hash = await fixture.ComputeInputIdentityAsync(path);
        var members = new ArchiveScanResult();
        foreach (string member in new[] { "one.txt", "two.txt" })
            members.Findings.Add(new SecurityFinding { ObjectPath = path + " -> " + member, ObjectName = member,
                SHA256 = hash, Category = FindingCategory.KnownMalwareHash, RiskLevel = RiskLevel.ConfirmedMalicious,
                RiskScore = 100, Title = "Synthetic contract evidence only" });
        var context = new DetectionContext { FilePath = path, SHA256 = hash };
        context.Properties["Ultron.ArchiveInspectionResult"] = members;
        var result = await new DetectionHub(initialDetectors: [new ArchiveDetectorPlugin()]).EvaluateAsync(context);
        Assert.Equal(2, result.Evidences.Count);
        Assert.Equal(2, result.Evidences.Select(e => e.FeatureIdentity).Distinct().Count());
        Assert.All(result.Evidences, e => Assert.Equal(path, e.FilePath));
    }

    /// <summary>Exclusions cannot hide synthetic authoritative proof in any live file inspection route; all actions are disabled.</summary>
    [Theory]
    [InlineData(EvidenceCategory.StaticSignature)]
    [InlineData(EvidenceCategory.AmsiProvider)]
    public async Task Exclusion_DoesNotEraseAuthoritativeEvidence(EvidenceCategory category)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("inert.txt", Encoding.UTF8.GetBytes("Synthetic evidence contract fixture, not malware."));
        var exclusions = new InertExclusions(true);
        var hub = new DetectionHub(initialDetectors: [new SyntheticAuthority(category)], exclusionService: exclusions);
        var context = new DetectionContext { FilePath = path, SHA256 = await fixture.ComputeInputIdentityAsync(path) };
        var result = await hub.EvaluateAsync(context);
        Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
        Assert.False(result.PolicyBypassed);
        var processor = new RealTimeVerdictProcessor(fixture.HashService, fixture.SignatureVerifier,
            new InertRisk(), null, null, exclusions, detectionHub: hub);
        Assert.Equal(RealTimeVerdict.ConfirmedMalicious, (await processor.InspectFileAsync(path)).Verdict);
        using var etw = new EtwPreExecProtectionService(hub, new InertRisk(), fixture.SignatureVerifier,
            exclusionService: exclusions, enableAutoQuarantine: () => false);
        var decision = await etw.EvaluateProcessAsync(int.MaxValue, path);
        Assert.Equal(100, decision.RiskScore);
        Assert.False(decision.Whitelisted);
        Assert.False(decision.WasBlocked);
        Assert.Contains("Confirmed threat", decision.Reason);
    }

    private sealed class SyntheticAuthority(EvidenceCategory category) : IDetectorPlugin
    {
        public string DetectorId => "SyntheticAuthorityFixture";
        public string DisplayName => DetectorId;
        public EvidenceCategory PrimaryCategory => category;
        public int Priority => 1;
        public bool IsEnabled { get; set; } = true;
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken ct = default)
            => Task.FromResult<IEnumerable<SecurityEvidence>>([new SecurityEvidence { Category = category,
                Confidence = EvidenceConfidence.Absolute, ScoreContribution = 100, FilePath = context.FilePath,
                SHA256 = context.SHA256, RuleName = "Synthetic.Test.Only", Description = "Synthetic authoritative proof contract" }]);
    }

    private sealed class InertResources : IScanResourceManager, IDisposable
    {
        public ScanResourceMode CurrentMode => ScanResourceMode.Low;
        public ScanResourceProfile ActiveProfile { get; } = new() { Concurrency = 1, MaximumConcurrency = 1, ChannelCapacity = 16 };
        public event Action<ScanResourceProfile>? ProfileChanged { add { } remove { } }
        public void SetMode(ScanResourceMode mode) { }
        public Task EnterWorkerSlotAsync(CancellationToken ct) => Task.CompletedTask;
        public void ExitWorkerSlot() { }
        public Task ApplyPacingAsync(int count, CancellationToken ct) => Task.CompletedTask;
        public void RefreshProfile() { }
        public void Dispose() { }
    }

    private sealed class InertRisk : IRiskScoringEngine
    {
        public Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(FileAnalysisResult result, CancellationToken ct = default)
            => Task.FromResult((0, RiskLevel.Clean, new List<string>()));
    }

    private sealed class InertExclusions(bool excluded) : IExclusionService
    {
        public bool IsExcluded(string? path, string? hash = null) => excluded;
        public Task<bool> IsExcludedAsync(string? path, string? hash = null, CancellationToken ct = default) => Task.FromResult(excluded);
        public Task<IReadOnlyList<ExclusionEntry>> GetAllExclusionsAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<ExclusionEntry>>([]);
        public Task<ExclusionEntry> AddPathExclusionAsync(string path, bool includeSubdirectories = true, string? reason = null, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ExclusionEntry> AddSha256ExclusionAsync(string hash, string? reason = null, CancellationToken ct = default) => throw new InvalidOperationException();
        public void AddTemporaryPathExclusion(string path, TimeSpan duration, string? reason = null) => throw new InvalidOperationException();
        public Task<bool> RemoveExclusionAsync(int id, CancellationToken ct = default) => throw new InvalidOperationException();
        public bool IsRootOrSystemDirectory(string path) => false;
        public Task InitializeAsync(CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class InertAllowlist : IAllowlistService
    {
        public bool IsAllowlisted(string hash) => false;
        public bool IsPathAllowlisted(string path) => false;
        public Task<bool> IsAllowlistedAsync(string hash, CancellationToken ct = default) => Task.FromResult(false);
        public Task<bool> IsPathAllowlistedAsync(string path, CancellationToken ct = default) => Task.FromResult(false);
        public Task AddToAllowlistAsync(AllowlistEntry entry, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task RemoveFromAllowlistAsync(int id, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<List<AllowlistEntry>> GetAllowlistAsync(CancellationToken ct = default) => Task.FromResult(new List<AllowlistEntry>());
        public Task<bool> CheckHashChangedAsync(AllowlistEntry entry, CancellationToken ct = default) => Task.FromResult(false);
    }
}
