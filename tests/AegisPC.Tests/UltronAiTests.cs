using AegisPC.Contracts.Detection;
using AegisPC.Core.Models;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Scanning;
using AegisPC.Security.UltronAI;
using Xunit;
using System.IO;
using System.Buffers.Binary;

namespace AegisPC.Tests;

/// <summary>Harmless locked-content and mathematical review fixtures; no malware or system settings are involved.</summary>
public sealed class UltronAiTests
{
    /// <summary>Null/missing/empty input cannot be represented as clean.</summary>
    [Fact]
    public async Task MissingInput_IsUnknownNotClean()
    {
        var engine = new UltronAiEngine();
        Assert.Equal(DetectionVerdict.Unknown, engine.EvaluateVector(null!).Verdict);
        Assert.Equal(DetectionVerdict.Unknown, engine.EvaluateVector(new()).Verdict);
        Assert.Equal(DetectionVerdict.Unknown, (await engine.EvaluateFileAsync(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".absent"))).Verdict);
    }
    /// <summary>Even a high handcrafted score cannot claim malware probability, confirmed malware or automatic block.</summary>
    [Fact]
    public void PackedStaticFeatures_NeverAuthorizeBlocking()
    {
        var vector = new UltronFeatureVector { Coverage = ContentClassificationCoverage.Complete,
            EntropyOverall = 7.9f, HasSuspiciousSectionName = true, HasWritableExecutableSection = true,
            HasProcessInjectionApis = true, DangerousApiRatio = 0.5f, HasTlsCallbacks = true, HasAntiDebuggingApis = true };
        var verdict = new UltronAiEngine().EvaluateVector(vector);
        Assert.Null(verdict.MalwareProbability);
        Assert.False(verdict.RequiresImmediateBlock);
        Assert.Equal(DetectionVerdict.Suspicious, verdict.Verdict);
        Assert.InRange(verdict.CalculatedRiskScore, 0, 60);
        Assert.Empty(verdict.MitreTactics);
        vector.IsSigned = vector.IsSignatureValid = vector.IsCommercialPublisher = vector.IsSystemLocation = true;
        Assert.Equal(verdict.CalculatedRiskScore, new UltronAiEngine().EvaluateVector(vector).CalculatedRiskScore);
    }
    /// <summary>A malformed executable under a safe-looking name is explicitly partial rather than clean.</summary>
    [Fact]
    public async Task MalformedPeWithImageExtension_IsPartial()
    {
        using var stream = new MemoryStream(new byte[] { 0x4d, 0x5a, 0, 0 });
        var classification = await new FileContentClassifier().ClassifyAsync(stream, ".jpg");
        var verdict = await new UltronAiEngine().EvaluateLockedFileAsync(stream, "synthetic.jpg", classification);
        Assert.NotEqual(DetectionVerdict.Clean, verdict.Verdict);
        Assert.NotEqual(ContentClassificationCoverage.Complete, verdict.Coverage);
        Assert.False(verdict.RequiresImmediateBlock);
    }
    /// <summary>Routing uses locked content even for renamed files and developer-package paths, and contributes no duplicate PE score.</summary>
    [Theory]
    [InlineData("C:/node_modules/fixture.jpg")]
    [InlineData("C:/Windows/fixture.data")]
    [InlineData("fixture")]
    public async Task PluginUsesLockedContent_NoPathOrExtensionBypass(string path)
    {
        var engine = new FixtureEngine();
        var classification = new FileContentClassification();
        using var stream = new MemoryStream(new byte[] { 1, 2, 3 });
        stream.Position = 1;
        var context = new ScanContext(path) { LockedContent = stream, ContentClassification = classification }.ToDetectionContext();
        var evidence = await new UltronAiDetectorPlugin(engine).EvaluateAsync(context);
        Assert.Equal(1, engine.LockedCalls);
        Assert.Empty(evidence);
        Assert.True(context.Properties.ContainsKey("UltronAiReviewPriority"));
        Assert.False(context.Properties.ContainsKey("UltronAiProbability"));
        Assert.True(stream.CanRead);
        Assert.Equal(1, stream.Position);
    }
    /// <summary>Feature extraction preserves a caller-owned stream, with supported non-PE scope distinct from safety.</summary>
    [Fact]
    public async Task SharedStreamPositionAndOwnership_ArePreserved()
    {
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("harmless fixture text"));
        var classification = await new FileContentClassifier().ClassifyAsync(stream, ".txt");
        stream.Position = 3;
        var vector = UltronFeatureExtractor.Extract(stream, "fixture.txt", classification);
        Assert.Equal(3, stream.Position);
        Assert.True(stream.CanRead);
        Assert.Equal(0, vector.SectionCount);
        Assert.NotEqual(DetectionVerdict.Clean, new UltronAiEngine().EvaluateVector(vector).Verdict);
    }
    /// <summary>Real cancellation propagates rather than turning into an unknown success.</summary>
    [Fact]
    public async Task CancelledInspection_Propagates()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new UltronAiEngine().EvaluateFileAsync("fixture", cancellation.Token));
    }
    /// <summary>Actual bounded PE metadata is parsed without reopening or executing the content, regardless of filename.</summary>
    [Theory]
    [InlineData("fixture.exe")]
    [InlineData("fixture.jpg")]
    public async Task ActualPeStructure_RenameDoesNotChangeFeatures(string name)
    {
        using var stream = new MemoryStream(PeFixture());
        var classification = await new FileContentClassifier().ClassifyAsync(stream, Path.GetExtension(name));
        var vector = UltronFeatureExtractor.Extract(stream, name, classification);
        Assert.Equal(1, vector.SectionCount);
        Assert.Equal(64, vector.SHA256.Length);
        Assert.Equal(ContentClassificationCoverage.Complete, vector.Coverage);
        Assert.NotEqual(DetectionVerdict.Clean, new UltronAiEngine().EvaluateVector(vector).Verdict);
    }
    /// <summary>Budget-limited PE metadata remains partial, not clean, while caller ownership and position are preserved.</summary>
    [Fact]
    public async Task LargePe_FeatureBudgetIsExplicit()
    {
        byte[] bytes = new byte[5 * 1024 * 1024];
        PeFixture().CopyTo(bytes, 0);
        using var stream = new MemoryStream(bytes);
        var classification = await new FileContentClassifier().ClassifyAsync(stream, ".data");
        stream.Position = 7;
        var vector = UltronFeatureExtractor.Extract(stream, "fixture.data", classification);
        Assert.Equal(ContentClassificationCoverage.Partial, vector.Coverage);
        Assert.Contains("PeFeatureByteBudgetExceeded", vector.CoverageLimitations);
        Assert.Equal(7, stream.Position);
        Assert.True(stream.CanRead);
    }
    /// <summary>Nonfinite handcrafted features cannot turn into an apparently complete assessment.</summary>
    [Theory]
    [InlineData(float.NaN)]
    [InlineData(float.PositiveInfinity)]
    public void InvalidVector_RemainsUnknown(float entropy)
    {
        var verdict = new UltronAiEngine().EvaluateVector(new UltronFeatureVector { EntropyOverall = entropy });
        Assert.Equal(DetectionVerdict.Unknown, verdict.Verdict);
        Assert.Contains("InvalidFeatureVector", verdict.CoverageLimitations);
    }
    private static byte[] PeFixture()
    {
        var bytes = new byte[1024];
        bytes[0] = 0x4d; bytes[1] = 0x5a;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 128);
        bytes[128] = 0x50; bytes[129] = 0x45;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(132), 0x14c);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(134), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(148), 224);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(150), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(152), 0x10b);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(152 + 60), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(152 + 224 + 16), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(152 + 224 + 20), 512);
        return bytes; // Data fixture only; never launched or written as a program.
    }

    private sealed class FixtureEngine : IUltronAiEngine
    {
        internal int LockedCalls;
        public Task<UltronAiVerdict> EvaluateFileAsync(string path, CancellationToken token = default) => throw new InvalidOperationException("Must use same locked source.");
        public Task<UltronAiVerdict> EvaluateLockedFileAsync(Stream source, string path, FileContentClassification classification, CancellationToken token = default)
        { LockedCalls++; return Task.FromResult(new UltronAiVerdict { CalculatedRiskScore = 60 }); }
        public UltronAiVerdict EvaluateVector(UltronFeatureVector vector) => new();
    }
}
