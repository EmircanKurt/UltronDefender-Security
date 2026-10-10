using System.IO;
using System.Text;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks rule certainty using inert disk files, synthetic matches and in-memory canonical test content.</summary>
public sealed class YaraCertaintySafetyTests
{
    /// <summary>Rule names, confidence metadata and file extensions cannot establish an exact content signature.</summary>
    [Theory]
    [InlineData("EICAR_Standard_Test_File", ".bin")]
    [InlineData("EICAR_Article_Reference", ".md")]
    [InlineData("UnrelatedRule", ".bin")]
    [InlineData("UnrelatedRule", ".txt")]
    [InlineData("Mimikatz_Reference", ".py")]
    public async Task InertFile_WithAssertedAbsoluteMatch_PreservesWarningWithoutCertainty(string ruleName, string extension)
    {
        string path = await WriteInertFileAsync(extension);
        try
        {
            var match = AssertedMatch(ruleName);
            var detector = new YaraDetector(new FixedEngine(match));
            var result = await new DetectionHub(new[] { detector }).EvaluateAsync(new DetectionContext { FilePath = path });

            var evidence = Assert.Single(result.Evidences);
            bool isTextDocument = extension is ".md" or ".txt" or ".py";
            Assert.Equal(isTextDocument ? EvidenceConfidence.Low : EvidenceConfidence.High, evidence.Confidence);
            Assert.InRange(evidence.ScoreContribution, 1, isTextDocument ? 25 : 84);
            Assert.Equal(isTextDocument ? EvidenceCategory.ScriptHeuristic : EvidenceCategory.StaticSignature, evidence.Category);
            Assert.NotEqual("ExactContentSignature", evidence.CorrelationGroup);
            Assert.NotEqual(DetectionVerdict.ConfirmedMalicious, result.Verdict);
            Assert.NotEqual(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
            Assert.Equal("absolute", evidence.Metadata["YaraMeta_confidence"]);
        }
        finally { File.Delete(path); }
    }

    /// <summary>An oversized local severity remains a bounded heuristic rather than an exact signature.</summary>
    [Fact]
    public async Task UntrustedSeverity_IsCappedWithoutSuppressingEvidence()
    {
        string path = await WriteInertFileAsync(".bin");
        try
        {
            var match = AssertedMatch("OrdinaryRule");
            match.Severity = int.MaxValue;
            var evidence = Assert.Single(await new YaraDetector(new FixedEngine(match))
                .EvaluateAsync(new DetectionContext { FilePath = path }));
            Assert.Equal(EvidenceConfidence.High, evidence.Confidence);
            Assert.Equal(84, evidence.ScoreContribution);
        }
        finally { File.Delete(path); }
    }

    /// <summary>A binary payload retains heuristic weight even when its filename ends in a text extension.</summary>
    [Fact]
    public async Task BinaryContentNamedTxt_IsNotDowngradedByExtension()
    {
        string path = Path.Combine(Path.GetTempPath(), "Ultron_YaraCertainty_" + Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            await File.WriteAllBytesAsync(path, Encoding.ASCII.GetBytes("inert certainty audit marker")
                .Concat(new byte[] { 0, 1, 2, 3 }).ToArray());
            var evidence = Assert.Single(await new YaraDetector(new FixedEngine(AssertedMatch("EICAR_Reference")))
                .EvaluateAsync(new DetectionContext { FilePath = path }));
            Assert.Equal(EvidenceCategory.StaticSignature, evidence.Category);
            Assert.Equal(EvidenceConfidence.High, evidence.Confidence);
            Assert.Equal(84, evidence.ScoreContribution);
        }
        finally { File.Delete(path); }
    }

    /// <summary>Incomplete rule byte coverage remains visible even when there is no matching evidence.</summary>
    [Fact]
    public async Task IncompleteCoverage_RemainsUnknown()
    {
        string path = await WriteInertFileAsync(".bin");
        try
        {
            var detector = new YaraDetector(new FixedEngine { MaximumScanBytes = 1 });
            var result = await new DetectionHub(new[] { detector }).EvaluateAsync(new DetectionContext { FilePath = path });
            Assert.False(result.IsComplete);
            Assert.Equal(DetectionVerdict.Unknown, result.Verdict);
            Assert.NotEmpty(result.CoverageLimitations);
        }
        finally { File.Delete(path); }
    }

    /// <summary>The real managed engine cannot promote a benign custom rule's self-declared certainty to confirmed malware.</summary>
    [Fact]
    public async Task RealEngine_InertCustomAbsoluteRule_IsNotConfirmedMalware()
    {
        string directory = Path.Combine(Path.GetTempPath(), "Ultron_YaraCertainty_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "inert.bin");
        try
        {
            const string rule = "rule InertAuditMarker {\nmeta:\n severity = 100\n confidence = \"absolute\"\nstrings:\n $marker = \"inert certainty audit marker\"\ncondition:\n $marker\n}";
            // Pre-existing inert rule files prevent the engine from writing its default test signature to disk.
            await File.WriteAllTextAsync(Path.Combine(directory, "eicar.yar"), rule);
            await File.WriteAllTextAsync(Path.Combine(directory, "mimikatz.yar"), "// no additional rules");
            await File.WriteAllTextAsync(Path.Combine(directory, "cobaltstrike.yar"), "// no additional rules");
            await File.WriteAllTextAsync(path, "inert certainty audit marker");
            var detector = new YaraDetector(new YaraEngine(directory));
            var result = await new DetectionHub(new[] { detector }).EvaluateAsync(new DetectionContext { FilePath = path });

            var evidence = Assert.Single(result.Evidences);
            Assert.Equal(EvidenceConfidence.High, evidence.Confidence);
            Assert.InRange(evidence.ScoreContribution, 1, 84);
            Assert.NotEqual(DetectionVerdict.ConfirmedMalicious, result.Verdict);
            Assert.Equal(DetectionPolicy.Warn, result.RecommendedPolicy);
        }
        finally { Directory.Delete(directory, true); }
    }

    /// <summary>The existing exact content and hash validators retain the canonical positive case entirely in memory.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(60)]
    public async Task CanonicalContent_StillMatchesInMemory(int trailingSpaces)
    {
        byte[] canonical = CanonicalBytes();
        byte[] content = canonical.Concat(Enumerable.Repeat((byte)' ', trailingSpaces)).ToArray();
        var match = MalwareSignatureDatabase.CheckBytesPattern(content);
        Assert.True(match.IsMatched);
        Assert.Equal("TestMalware", match.ThreatCategory);
        Assert.True(MalwareSignatureDatabase.CheckHash(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(canonical))).IsMatched);
        Assert.True(await CheckDetectorCanonicalContentAsync(content));
    }

    /// <summary>A canonical substring inside a longer document is not an exact test file.</summary>
    [Fact]
    public async Task CanonicalReference_InLongerMemoryDocument_IsNotCanonical()
    {
        byte[] document = Encoding.ASCII.GetBytes("Educational reference: ").Concat(CanonicalBytes()).ToArray();
        Assert.False(MalwareSignatureDatabase.CheckBytesPattern(document).IsMatched);
        Assert.False(await CheckDetectorCanonicalContentAsync(document));
    }

    /// <summary>The bounded verifier rejects overlong content and invalid suffixes without any test file on disk.</summary>
    [Theory]
    [InlineData(61, 32)]
    [InlineData(0, 0)]
    [InlineData(0, 12)]
    public async Task CanonicalContent_InvalidSuffixIsNotExact(int padding, int finalByte)
    {
        byte[] bytes = CanonicalBytes().Concat(Enumerable.Repeat((byte)' ', padding)).Concat(new[] { checked((byte)finalByte) }).ToArray();
        Assert.False(await CheckDetectorCanonicalContentAsync(bytes));
    }

    private static async Task<bool> CheckDetectorCanonicalContentAsync(byte[] bytes)
    {
        var method = typeof(YaraDetector).GetMethod("IsCanonicalTestContentAsync",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);
        using var stream = new MemoryStream(bytes, writable: false);
        return await (Task<bool>)method.Invoke(null, new object[] { stream, CancellationToken.None })!;
    }

    private static byte[] CanonicalBytes() => Encoding.ASCII.GetBytes(string.Concat(
        "X5O!P%@AP[4\\", "PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"));

    private static async Task<string> WriteInertFileAsync(string extension)
    {
        string path = Path.Combine(Path.GetTempPath(), "Ultron_YaraCertainty_" + Guid.NewGuid().ToString("N") + extension);
        await File.WriteAllTextAsync(path, "inert certainty audit marker");
        return path;
    }

    private static YaraMatch AssertedMatch(string ruleName) => new()
    {
        RuleName = ruleName,
        Severity = 100,
        Description = "Synthetic rule result for inert content",
        Metadata = new(StringComparer.OrdinalIgnoreCase) { ["confidence"] = "absolute" },
        MatchedStrings = new() { new YaraStringMatch { Identifier = "$marker", Offset = 0, MatchedValue = "inert certainty audit marker" } }
    };

    private sealed class FixedEngine : IYaraEngine
    {
        private readonly List<YaraMatch> _matches;
        public FixedEngine(params YaraMatch[] matches) => _matches = matches.ToList();
        public int LoadedRuleCount => 1;
        public long? MaximumScanBytes { get; init; }
        public string RulesDirectory => string.Empty;
        public void ReloadRules() { }
        public Task<List<YaraMatch>> ScanFileAsync(string filePath, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(_matches);
        }
        public Task<List<YaraMatch>> ScanBufferAsync(byte[] buffer, string identifier = "", CancellationToken ct = default) =>
            ScanFileAsync(identifier, ct);
    }
}
