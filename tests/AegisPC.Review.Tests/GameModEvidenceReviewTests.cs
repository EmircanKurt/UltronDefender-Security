using AegisPC.Contracts.Detection;
using System.IO;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Inert evidence fixtures: no binaries are executed and no host protection actions are invoked.</summary>
public sealed class GameModEvidenceReviewTests
{
    /// <summary>Capabilities form one pool outside category caps; detector order must not change the decision.</summary>
    [Fact]
    public async Task CapabilityPoolIsDeterministicAcrossPermutationsAndDuplicates()
    {
        var evidence = new[]
        {
            Item("malformed", EvidenceCategory.StaticPeStructure, EvidenceNature.StructuralAnomaly, 40),
            Item("packing", EvidenceCategory.StaticPeStructure, EvidenceNature.Capability, 25),
            Item("imports", EvidenceCategory.StaticApi, EvidenceNature.Capability, 20)
        };
        foreach (var order in new[] { evidence, evidence.Reverse().ToArray(), new[] { evidence[1], evidence[0], evidence[2], evidence[1] } })
        {
            var result = await new DetectionHub([new FixtureDetector(order)]).EvaluateAsync(new DetectionContext());
            Assert.Equal(65, result.RiskScore);
            Assert.Equal(DetectionVerdict.Suspicious, result.Verdict);
            Assert.Equal(DetectionPolicy.Warn, result.RecommendedPolicy);
        }
    }

    /// <summary>A benign packed overlay's ordinary measured capabilities cannot independently reach warning thresholds.</summary>
    [Fact]
    public async Task OrdinaryCapabilitiesAreCappedGlobally()
    {
        var result = await new DetectionHub([new FixtureDetector([
            Item("wx", EvidenceCategory.StaticPeStructure, EvidenceNature.Capability, 35),
            Item("entropy", EvidenceCategory.EntropyAnomaly, EvidenceNature.Capability, 25),
            Item("packing", EvidenceCategory.AntiEvasion, EvidenceNature.Capability, 30),
            Item("imports", EvidenceCategory.StaticApi, EvidenceNature.Capability, 25)])]).EvaluateAsync(new DetectionContext());
        Assert.Equal(25, result.RiskScore);
        Assert.Equal(DetectionVerdict.Clean, result.Verdict);
        Assert.Equal(DetectionPolicy.Allow, result.RecommendedPolicy);
    }

    /// <summary>No shared motor means incomplete inspection, never a fallback name/location heuristic.</summary>
    [Theory]
    [InlineData(@"C:\Tools\normal.exe")]
    [InlineData(@"C:\İndirilenler\crack_keygen_patcher.exe")]
    public async Task LegacyWithoutSharedEngineReturnsUnknown(string path)
    {
        var result = await new RiskScoringEngine().CalculateRiskScoreAsync(new FileAnalysisResult { FilePath = path, FileName = Path.GetFileName(path) });
        Assert.Equal(RiskLevel.Unknown, result.level);
        Assert.Equal(0, result.score);
    }

    internal static SecurityEvidence Item(string feature, EvidenceCategory category, EvidenceNature nature, int score) => new()
    {
        FeatureIdentity = feature, SourceDetector = "inert", Category = category, Nature = nature,
        ScoreContribution = score, CorrelationGroup = feature, RuleName = feature, Confidence = EvidenceConfidence.High
    };

    /// <summary>Equal-score collisions choose the same representative and cannot let a label shadow real evidence.</summary>
    [Fact]
    public async Task EqualFeatureTiesAndOptionalLabelsDoNotDependOnOrder()
    {
        var capability = Item("same", EvidenceCategory.StaticPeStructure, EvidenceNature.Capability, 50);
        var independent = Item("same", EvidenceCategory.StaticPeStructure, EvidenceNature.Heuristic, 50);
        var label = Item("same", EvidenceCategory.StaticSignature, EvidenceNature.SoftwareClassification, 100);
        label.Confidence = EvidenceConfidence.Absolute;
        foreach (var order in new[] { new[] { capability, independent, label }, new[] { label, independent, capability } })
        {
            var result = await new DetectionHub([new FixtureDetector(order)]).EvaluateAsync(new DetectionContext());
            Assert.Equal(40, result.RiskScore); // Existing StaticPeStructure cap is intentionally unchanged.
            Assert.Equal(DetectionVerdict.LowRisk, result.Verdict);
            Assert.Equal(DetectionPolicy.Observe, result.RecommendedPolicy);
            Assert.Equal(SoftwareFindingClass.MalwareConcern, result.SoftwareClass);
            Assert.False(label.IsExactMalwareEvidence);
        }
    }

    /// <summary>Missing or changed legacy input cannot be interpreted as empty clean evidence by an available shared engine.</summary>
    [Fact]
    public async Task LegacyAdapterRequiresCurrentContentIdentity()
    {
        var hub = new DetectionHub([new FixtureDetector([])]);
        var adapter = new RiskScoringEngine(detectionHub: hub);
        string path = Path.Combine(Path.GetTempPath(), "Ultron-Legacy-" + Guid.NewGuid().ToString("N") + ".txt");
        var missing = await adapter.CalculateRiskScoreAsync(new FileAnalysisResult { FilePath = path });
        Assert.Equal(RiskLevel.Unknown, missing.level);
        await File.WriteAllTextAsync(path, "ordinary documentation");
        var changed = await adapter.CalculateRiskScoreAsync(new FileAnalysisResult { FilePath = path, SHA256 = new string('A', 64) });
        Assert.Equal(RiskLevel.Unknown, changed.level);
        var complete = await adapter.CalculateRiskScoreAsync(new FileAnalysisResult { FilePath = path });
        Assert.Equal(RiskLevel.Clean, complete.level);
    }

    internal sealed class FixtureDetector(SecurityEvidence[] evidence) : IDetectorPlugin
    {
        public string DetectorId => "inert-fixture";
        public string DisplayName => "Inert fixture";
        public bool IsEnabled { get; set; } = true;
        public int Priority => 1;
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticPeStructure;
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult<IEnumerable<SecurityEvidence>>(evidence); }
    }
}
