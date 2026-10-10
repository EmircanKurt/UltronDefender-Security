using System.IO;
using System.Text;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Owned benign temporary content with inert signature, detector and action boundaries. No native observers.</summary>
public sealed class ReviewStageACoverageTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompletedInspection_ExplicitlyCertifiesCoverage(bool hubRoute)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("An ordinary coverage note."));
        var hub = new DetectionHub(initialDetectors: [new InertDetector(false)]);
        var result = await Processor(fixture, hubRoute ? hub : null).InspectFileAsync(path);
        Assert.True(result.InspectionComplete);
        Assert.False(result.PolicyBypassed);
        Assert.Equal(RealTimeVerdict.Clean, result.Verdict);
        Assert.Empty(result.CoverageLimitations);
    }

    [Fact]
    public async Task FailedDetector_CannotCertifyCleanCoverage()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("A harmless detector failure fixture."));
        var result = await Processor(fixture, new DetectionHub(initialDetectors: [new InertDetector(true)]))
            .InspectFileAsync(path);
        Assert.False(result.InspectionComplete);
        Assert.Equal(RealTimeVerdict.Unknown, result.Verdict);
        Assert.Contains("DetectorExecutionFailed", result.CoverageLimitations);
    }

    [Fact]
    public async Task PartialClassification_CannotBeOverriddenByACompleteHub()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("Benign classifier fault fixture."));
        var result = await new RealTimeVerdictProcessor(fixture.HashService, fixture.SignatureVerifier, new InertRisk(),
            null, null, null, detectionHub: new CompleteHub(), contentClassifier: new PartialClassifier()).InspectFileAsync(path);
        Assert.False(result.InspectionComplete);
        Assert.Equal(RealTimeVerdict.Unknown, result.Verdict);
        Assert.Contains("FixtureClassificationGap", result.CoverageLimitations);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Exclusion_SkipsDeepInspectionWithoutCreatingACleanCache(bool hubRoute)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("Harmless exclusion and cache fixture."));
        var exclusions = new InertExclusions();
        var detector = new InertDetector(false);
        var hub = new DetectionHub(initialDetectors: [detector], exclusionService: exclusions);
        var matcher = new FileHashMatcher(fixture.HashService, fixture.SignatureVerifier, null!);
        var processor = new RealTimeVerdictProcessor(fixture.HashService, fixture.SignatureVerifier, new InertRisk(),
            matcher, null, exclusions, detectionHub: hubRoute ? hub : null);
        for (int i = 0; i < 2; i++)
        {
            var result = await processor.InspectFileAsync(path);
            Assert.False(result.InspectionComplete);
            Assert.True(result.PolicyBypassed);
            Assert.Equal(RealTimeVerdict.Unknown, result.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, result.RecommendedPolicy);
            Assert.Contains(result.CoverageLimitations, reason => reason.StartsWith("UserExclusion", StringComparison.Ordinal));
        }
        Assert.Equal(0, detector.Calls);
        Assert.Equal(0, matcher.CachedEntriesCount);
    }

    [Fact]
    public async Task ExistingCleanCache_DoesNotOverrideNewExclusion()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("Harmless existing cache fixture."));
        string hash = await fixture.ComputeInputIdentityAsync(path);
        var info = new FileInfo(path);
        var matcher = new FileHashMatcher(fixture.HashService, fixture.SignatureVerifier, null!);
        matcher.SetCache(path, info.Length, info.LastWriteTimeUtc, null, hash, false, false);
        var result = await new RealTimeVerdictProcessor(fixture.HashService, fixture.SignatureVerifier, new InertRisk(),
            matcher, null, new InertExclusions()).InspectFileAsync(path);
        Assert.True(result.PolicyBypassed);
        Assert.False(result.InspectionComplete);
        Assert.Equal(RealTimeVerdict.Unknown, result.Verdict);
    }

    [Fact]
    public async Task SyntheticExactHash_RemainsVisibleDespiteUserExclusion()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("Inert exact-priority stub. No malware content."));
        var result = await new RealTimeVerdictProcessor(new SyntheticHash(), fixture.SignatureVerifier, new InertRisk(),
            null, null, new InertExclusions()).InspectFileAsync(path);
        Assert.Equal(RealTimeVerdict.ConfirmedMalicious, result.Verdict);
        Assert.Equal(RealTimePolicyAction.BlockAndQuarantine, result.RecommendedPolicy);
        Assert.False(result.PolicyBypassed);
        Assert.False(result.InspectionComplete);
        Assert.Contains("ExactSignatureOnly", result.CoverageLimitations);
        Assert.NotEmpty(result.Evidences);
    }

    private static RealTimeVerdictProcessor Processor(ReviewStageOneFixture fixture, IDetectionHub? hub) =>
        new(fixture.HashService, fixture.SignatureVerifier, new InertRisk(), null, null, null, detectionHub: hub);

    [Fact]
    public async Task HubOnlyExclusion_PreservesPermissionAndCoverageAtTheAdapter()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("Benign hub-only exclusion fixture."));
        var detector = new InertDetector(false);
        var hub = new DetectionHub(initialDetectors: [detector], exclusionService: new InertExclusions());
        var result = await Processor(fixture, hub).InspectFileAsync(path);
        Assert.True(result.PolicyBypassed);
        Assert.False(result.InspectionComplete);
        Assert.Equal(RealTimePolicyAction.Allow, result.RecommendedPolicy);
        Assert.Equal(RealTimeVerdict.Unknown, result.Verdict);
        Assert.Contains(result.CoverageLimitations, reason => reason.StartsWith("UserExclusion", StringComparison.Ordinal));
        Assert.Equal(0, detector.Calls);
    }

    [Fact]
    public async Task ExclusionAddedDuringAnalysis_PreservesEvidenceWithoutCachingClean()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("note.txt", Encoding.UTF8.GetBytes("Harmless changing-policy fixture."));
        bool excluded = false;
        var matcher = new FileHashMatcher(fixture.HashService, fixture.SignatureVerifier, null!);
        var result = await new RealTimeVerdictProcessor(fixture.HashService, fixture.SignatureVerifier,
            new InertRisk(() => excluded = true, 60), matcher, null, new InertExclusions(() => excluded)).InspectFileAsync(path);
        Assert.True(result.PolicyBypassed);
        Assert.False(result.InspectionComplete);
        Assert.Equal(RealTimeVerdict.Suspicious, result.Verdict);
        Assert.Equal(RealTimePolicyAction.Allow, result.RecommendedPolicy);
        Assert.Equal(60, result.RiskScore);
        Assert.Contains("Inert review evidence", result.Evidences);
        Assert.Equal(0, matcher.CachedEntriesCount);
    }

    private sealed class InertRisk(Action? duringAnalysis = null, int score = 0) : IRiskScoringEngine
    {
        public Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(FileAnalysisResult result, CancellationToken ct = default)
        {
            duringAnalysis?.Invoke();
            return Task.FromResult((score, score >= 50 ? RiskLevel.Suspicious : RiskLevel.Clean,
                score >= 50 ? new List<string> { "Inert review evidence" } : new List<string>()));
        }
    }
    private sealed class InertDetector(bool fail) : IDetectorPlugin
    {
        public int Calls;
        public string DetectorId => "StageAInert";
        public string DisplayName => DetectorId;
        public EvidenceCategory PrimaryCategory => EvidenceCategory.ScriptHeuristic;
        public int Priority => 1;
        public bool IsEnabled { get; set; } = true;
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken ct = default)
        {
            Calls++;
            if (fail) throw new IOException("Inert injected detector failure.");
            return Task.FromResult<IEnumerable<SecurityEvidence>>([]);
        }
    }
    private sealed class CompleteHub : IDetectionHub
    {
        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => [];
        public void RegisterDetector(IDetectorPlugin detector) => throw new NotSupportedException();
        public bool UnregisterDetector(string detectorId) => false;
        public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(new DetectionResult { Verdict = DetectionVerdict.Clean, IsComplete = true, RecommendedPolicy = DetectionPolicy.Allow });
    }
    private sealed class PartialClassifier : IFileContentClassifier
    {
        public Task<FileContentClassification> ClassifyAsync(Stream source, string? declaredExtension, CancellationToken cancellationToken = default)
            => Task.FromResult(new FileContentClassification { Coverage = ContentClassificationCoverage.Partial,
                CoverageLimitations = { "FixtureClassificationGap" } });
    }
    private sealed class SyntheticHash : IHashService
    {
        // Catalog identity supplied by a fake; bytes on disk are ordinary text, with no action adapter.
        public Task<string> ComputeSha256Async(string path, CancellationToken ct = default)
            => Task.FromResult("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F");
        public Task<string> ComputeSha1Async(string path, CancellationToken ct = default) => Task.FromResult(new string('A', 40));
    }
    private sealed class InertExclusions(Func<bool>? isExcluded = null) : IExclusionService
    {
        public bool IsExcluded(string? path, string? hash = null) => isExcluded?.Invoke() ?? true;
        public Task<bool> IsExcludedAsync(string? path, string? hash = null, CancellationToken ct = default) => Task.FromResult(IsExcluded(path, hash));
        public Task<IReadOnlyList<ExclusionEntry>> GetAllExclusionsAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<ExclusionEntry>>([]);
        public Task<ExclusionEntry> AddPathExclusionAsync(string path, bool includeSubdirectories = true, string? reason = null, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ExclusionEntry> AddSha256ExclusionAsync(string hash, string? reason = null, CancellationToken ct = default) => throw new InvalidOperationException();
        public void AddTemporaryPathExclusion(string path, TimeSpan duration, string? reason = null) => throw new InvalidOperationException();
        public Task<bool> RemoveExclusionAsync(int id, CancellationToken ct = default) => throw new InvalidOperationException();
        public bool IsRootOrSystemDirectory(string path) => false;
        public Task InitializeAsync(CancellationToken ct = default) => Task.CompletedTask;
    }
}

// Reuses the existing startup recording engine/vault: neither touches installed protection or a real vault.
public sealed partial class StartupSweepSafetyTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task StageA_UnverifiedCleanOrPolicyBypass_IsNeverCountedOrCachedAsClean(bool complete, bool bypass)
    {
        string path = CreateBenignFile("Ordinary startup coverage fixture.");
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean,
            InspectionComplete = complete, PolicyBypassed = bypass, RecommendedPolicy = RealTimePolicyAction.Allow,
            SHA256 = ValidHash(path), CoverageLimitations = [bypass ? "UserExclusion" : "FixtureGap"] });
        var vault = new RecordingVault();
        var sweep = new StartupSecuritySweepService(engine, vault);
        for (int i = 0; i < 2; i++)
        {
            var result = await sweep.RunSweepAsync([path]);
            Assert.Equal(0, result.CleanCount);
            Assert.Equal(1, result.IncompleteCount);
            Assert.Equal(bypass ? 1 : 0, result.PolicyBypassCount);
            Assert.Equal(0, result.SkippedCount);
            var finding = Assert.Single(result.Findings);
            Assert.False(finding.InspectionComplete);
            Assert.Equal(bypass, finding.PolicyBypassed);
            Assert.NotEmpty(finding.CoverageLimitations);
        }
        Assert.Equal(2, engine.Inspections);
        Assert.Equal(0, vault.BoundCalls);
        Assert.Equal(0, vault.UnboundCalls);
    }

    [Fact]
    public async Task StageA_ExplicitlyCompleteClean_IsCachedWithItsCoverage()
    {
        string path = CreateBenignFile("Complete startup coverage fixture.");
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean,
            InspectionComplete = true, RecommendedPolicy = RealTimePolicyAction.Allow, SHA256 = ValidHash(path) });
        var sweep = new StartupSecuritySweepService(engine, new RecordingVault());
        await sweep.RunSweepAsync([path]);
        var second = await sweep.RunSweepAsync([path]);
        Assert.Equal(1, engine.Inspections);
        Assert.Equal(1, second.CleanCount);
        Assert.Equal(1, second.SkippedCount);
        Assert.Equal(0, second.IncompleteCount);
    }
}
