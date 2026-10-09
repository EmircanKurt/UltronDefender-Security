using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;
using AegisPC.Contracts.PE;
using AegisPC.Security.PE;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Enums;
using AegisPC.Security;
using AegisPC.Security.Archive;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Real benign payload/ZIP/JAR fixtures; no execution, extraction, malware download or host actions.</summary>
public sealed class GameModArchiveParityReviewTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "Ultron-Parity-" + Guid.NewGuid().ToString("N"));
    public GameModArchiveParityReviewTests() => Directory.CreateDirectory(_root);

    /// <summary>Names and archive wrapping do not turn generic API documentation into malware.</summary>
    [Theory]
    [InlineData("normal.dll", ".zip")]
    [InlineData("crack_keygen.dll", ".jar")]
    [InlineData("Türkçe_mod.jpg", ".zip")]
    public async Task GenericReferencesKeepCapabilitySemantics(string name, string extension)
    {
        byte[] payload = Encoding.UTF8.GetBytes("Documentation: VirtualAlloc WriteProcessMemory CreateRemoteThread are API references, not calls.\n");
        string file = Path.Combine(_root, name); await File.WriteAllBytesAsync(file, payload);
        var outside = await new DetectionHub([new HashSignatureDetector(new HashService()), new ScriptHeuristicDetector()])
            .EvaluateAsync(new DetectionContext { FilePath = file });
        string archivePath = Path.Combine(_root, "payload" + extension);
        using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
        { using var member = archive.CreateEntry(name).Open(); member.Write(payload); }
        var context = new DetectionContext { FilePath = archivePath, SHA256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(archivePath))) };
        var inside = await new DetectionHub([new ArchiveDetectorPlugin()]).EvaluateAsync(context);
        Assert.Equal(outside.RiskScore, inside.RiskScore);
        Assert.Equal(outside.Verdict, inside.Verdict);
        Assert.Equal(outside.RecommendedPolicy, inside.RecommendedPolicy);
        Assert.All(inside.Evidences.Where(e => e.ScoreContribution > 0), e => Assert.Equal(EvidenceNature.Capability, e.Nature));
        foreach (var e in inside.Evidences)
        {
            Assert.Equal(context.SHA256, e.SHA256);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(payload)), e.Metadata["ArchiveMemberSHA256"]);
        }
    }

    /// <summary>Corruption or unsupported member structures cannot become complete clean scans.</summary>
    [Fact]
    public async Task UnknownMemberRemainsPartial()
    {
        string file = Path.Combine(_root, "unknown.zip");
        using (var archive = ZipFile.Open(file, ZipArchiveMode.Create))
        { using var member = archive.CreateEntry("renamed.dll").Open(); member.Write(new byte[] { 0,1,2,3,4,5 }); }
        var result = await new ArchiveSafetyScanner().ScanArchiveAsync(file);
        Assert.False(result.IsComplete); Assert.NotNull(result.CoverageLimitation);
        Assert.Equal(1, result.HashedMembers);
    }

    /// <summary>Accumulation cannot recursively reinsert its combined display string and grow without bound.</summary>
    [Fact]
    public void RepeatedCoverageGapsRemainBounded()
    {
        var result = new ArchiveScanResult { CoverageLimitation = "nested archive gap" };
        for (int i = 0; i < 10000; i++) result.RecordCoverageGap("member gap " + (i % 3));
        Assert.Equal(4, result.CoverageLimitations.Count);
        Assert.True(result.CoverageLimitation!.Length < 200);
        Assert.False(result.IsComplete);
    }

    /// <summary>Inert modified copy of a local built managed binary retains the same W+X/packing static features inside ZIP.</summary>
    [Fact]
    public async Task BoundedPeMemberReusesLooseStaticRuleSemantics()
    {
        byte[] payload = await File.ReadAllBytesAsync(typeof(AegisPC.Core.Models.SecurityFinding).Assembly.Location);
        int header = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(0x3c));
        int section = header + 24 + BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(header + 20));
        Encoding.ASCII.GetBytes("UPX0\0\0\0\0").CopyTo(payload, section);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(section + 36));
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(section + 36), flags | 0xa0000000);
        string file = Path.Combine(_root, "benign-static-fixture.dll"); await File.WriteAllBytesAsync(file, payload);
        var outside = await new DetectionHub([new DeepPeDetector(new BufferAnalyzer(payload))])
            .EvaluateAsync(new DetectionContext { FilePath = file });
        string packed = Path.Combine(_root, "pe.zip");
        using (var archive = ZipFile.Open(packed, ZipArchiveMode.Create))
        { using var member = archive.CreateEntry("crack_fixture.jpg").Open(); member.Write(payload); }
        var inside = await new DetectionHub([new ArchiveDetectorPlugin()]).EvaluateAsync(new DetectionContext { FilePath = packed });
        Assert.Equal(25, outside.RiskScore); Assert.Equal(outside.RiskScore, inside.RiskScore);
        foreach (var item in outside.Evidences.Where(e => e.ScoreContribution > 0))
            Assert.Contains(inside.Evidences, e => e.RuleName == item.RuleName && e.Nature == item.Nature && e.ScoreContribution == item.ScoreContribution);
        Assert.False(inside.IsComplete);
        Assert.Contains(inside.CoverageLimitations, gap => gap.Contains("Authenticode", StringComparison.Ordinal));
    }

    private sealed class BufferAnalyzer(byte[] payload) : IDeepPeAnalyzer
    {
        public PeDeepAnalysisResult Analyze(byte[] bytes, string path = "") => new DeepPeAnalyzer().Analyze(bytes, path);
        public Task<PeDeepAnalysisResult> AnalyzeAsync(string path, CancellationToken ct = default)
        { ct.ThrowIfCancellationRequested(); return Task.FromResult(Analyze(payload, path)); }
    }

    /// <summary>Configured benign marker rules preserve category/group/score across text and binary archive wrapping.</summary>
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task ConfiguredYaraRulesUseSharedMapping(bool text)
    {
        var engine = new YaraEngine(Path.Combine(_root, "rules"));
        await File.WriteAllTextAsync(Path.Combine(engine.RulesDirectory, "parity.yar"),
            "rule Benign_Parity { meta: severity = 84 strings: $a = \"inert-rule-parity-marker\" condition: $a }");
        engine.ReloadRules();
        byte[] marker = Encoding.UTF8.GetBytes("inert-rule-parity-marker");
        byte[] payload = text ? marker : new byte[] { 0, 0xff, 0 }.Concat(marker).ToArray();
        string file = Path.Combine(_root, "keygen_fixture.bin"); await File.WriteAllBytesAsync(file, payload);
        var outside = await new DetectionHub([new YaraDetector(engine)]).EvaluateAsync(new DetectionContext { FilePath = file });
        string zip = Path.Combine(_root, "rules.jar");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        { using var member = archive.CreateEntry("readme.dat").Open(); member.Write(payload); }
        var inside = await new DetectionHub([new ArchiveDetectorPlugin(memberScanner: new ArchiveSafetyScanner(yaraEngine: engine))])
            .EvaluateAsync(new DetectionContext { FilePath = zip });
        Assert.NotEmpty(outside.Evidences);
        Assert.Equal(outside.RiskScore, inside.RiskScore);
        foreach (var evidence in outside.Evidences)
            Assert.Contains(inside.Evidences, member => member.RuleName == evidence.RuleName && member.Category == evidence.Category &&
                member.CorrelationGroup == evidence.CorrelationGroup && member.Nature == evidence.Nature && member.ScoreContribution == evidence.ScoreContribution);
        Assert.DoesNotContain(inside.Evidences, e => e.IsExactMalwareEvidence);
    }

    public void Dispose() => Directory.Delete(_root, true); // Unique fixture root owned solely by this test.
}
