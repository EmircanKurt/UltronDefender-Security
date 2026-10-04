using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Benign structural fixtures test routing and honest coverage without executing payloads or creating malware.</summary>
public sealed class FileContentClassificationTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "UltronContentIdentity_" + Guid.NewGuid().ToString("N"));

    /// <summary>Creates an isolated fixture root; no installed product state is accessed.</summary>
    public FileContentClassificationTests() => Directory.CreateDirectory(_root);

    [Theory]
    [InlineData(".exe", false)]
    [InlineData(".jpg", true)]
    [InlineData("", false)]
    public async Task PeIdentityDependsOnValidatedStructureRatherThanExtension(string extension, bool mismatch)
    {
        using var source = new MemoryStream(PeFixture());
        source.Position = 17;
        var result = await new FileContentClassifier().ClassifyAsync(source, extension);
        Assert.Contains(FileContentFormat.PortableExecutable, result.ValidatedFormats);
        Assert.Equal(mismatch, result.HasExtensionMismatch);
        Assert.True(result.IsComplete);
        Assert.Equal(17, source.Position);
    }

    [Theory]
    [InlineData(".jpg")]
    [InlineData(".exe")]
    public async Task MzAloneDoesNotEstablishValidatedPeOrCompleteCoverage(string extension)
    {
        using var source = new MemoryStream("MZnot a PE image"u8.ToArray());
        var result = await new FileContentClassifier().ClassifyAsync(source, extension);
        Assert.Contains(FileContentFormat.PortableExecutable, result.Formats);
        Assert.DoesNotContain(FileContentFormat.PortableExecutable, result.ValidatedFormats);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public async Task PeSectionOutsideSourceIsExplicitlyPartial()
    {
        byte[] bytes = PeFixture();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(128 + 24 + 224 + 16), uint.MaxValue);
        using var source = new MemoryStream(bytes);
        var result = await new FileContentClassifier().ClassifyAsync(source, ".exe");
        Assert.False(result.IsComplete);
        Assert.DoesNotContain(FileContentFormat.PortableExecutable, result.ValidatedFormats);
    }

    [Theory]
    [InlineData(".jar")]
    [InlineData(".jpg")]
    [InlineData("")]
    public async Task JarContentRoutesAsZipUnderEveryName(string extension)
    {
        using var source = ZipFixture(("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n"), ("example.txt", "harmless data"));
        var result = await new FileContentClassifier().ClassifyAsync(source, extension);
        Assert.True(result.RequiresZipInspection);
        Assert.Contains(FileContentFormat.Zip, result.ValidatedFormats);
        Assert.Contains(FileContentFormat.JavaArchive, result.Formats);
        Assert.Equal(2, result.DeclaredArchiveEntryCount);
        Assert.Equal(2, result.ArchiveMembers.Count);
        Assert.True(result.IsComplete);
    }

    [Fact]
    public async Task OfficePackageMetadataIsReportedWithoutTrustingDocumentName()
    {
        using var source = ZipFixture(("[Content_Types].xml", "<Types/>"), ("_rels/.rels", "<Relationships/>"), ("word/document.xml", "<document/>"));
        var result = await new FileContentClassifier().ClassifyAsync(source, ".bin");
        Assert.Contains(FileContentFormat.OfficeOpenXml, result.Formats);
        Assert.True(result.RequiresZipInspection);
        Assert.False(result.IsAmbiguous);
    }

    [Fact]
    public async Task PeWithAppendedZipRetainsBothApplicableRoutes()
    {
        using var zip = ZipFixture(("readme.txt", "harmless data"));
        using var source = new MemoryStream(PeFixture().Concat(zip.ToArray()).ToArray());
        var result = await new FileContentClassifier().ClassifyAsync(source, ".exe");
        Assert.Contains(FileContentFormat.PortableExecutable, result.ValidatedFormats);
        Assert.Contains(FileContentFormat.Zip, result.ValidatedFormats);
        Assert.True(result.IsAmbiguous);
        Assert.True(result.RequiresZipInspection);
    }

    [Fact]
    public async Task ZipLocalHeaderOutsideFileIsPartialRatherThanClean()
    {
        using var zip = ZipFixture(("readme.txt", "harmless"));
        byte[] bytes = zip.ToArray();
        int central = FindSignature(bytes, 0x02014b50);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 42), uint.MaxValue - 1);
        using var source = new MemoryStream(bytes);
        var result = await new FileContentClassifier().ClassifyAsync(source, ".zip");
        Assert.False(result.IsComplete);
        Assert.NotEmpty(result.CoverageLimitations);
    }

    [Fact]
    public async Task EncryptedZipMetadataDoesNotReportCompleteContent()
    {
        using var zip = ZipFixture(("readme.txt", "harmless"));
        byte[] bytes = zip.ToArray();
        int central = FindSignature(bytes, 0x02014b50);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(central + 8), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(6), 1);
        using var source = new MemoryStream(bytes);
        var result = await new FileContentClassifier().ClassifyAsync(source, ".zip");
        Assert.False(result.IsComplete);
        Assert.True(Assert.Single(result.ArchiveMembers).IsEncrypted);
    }

    [Fact]
    public async Task UnknownBinaryAndUnsupportedContainerNeverBecomeComplete()
    {
        using var unknown = new MemoryStream(new byte[] { 0, 1, 2, 3, 0xff });
        var binary = await new FileContentClassifier().ClassifyAsync(unknown, ".jpg");
        Assert.Equal(ContentClassificationCoverage.Unknown, binary.Coverage);
        using var gzip = new MemoryStream(new byte[] { 0x1f, 0x8b, 8, 0, 0, 0 });
        var container = await new FileContentClassifier().ClassifyAsync(gzip, ".bin");
        Assert.Contains(FileContentFormat.UnsupportedContainer, container.Formats);
        Assert.Equal(ContentClassificationCoverage.Unsupported, container.Coverage);
    }

    [Fact]
    public async Task ShortcutTargetIsNotFollowedAndPdfObjectsRemainPartial()
    {
        var link = new byte[76];
        link[0] = 0x4c;
        new byte[] { 1, 20, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46 }.CopyTo(link, 4);
        using var source = new MemoryStream(link);
        var result = await new FileContentClassifier().ClassifyAsync(source, ".txt");
        Assert.Contains(FileContentFormat.WindowsShortcut, result.Formats);
        Assert.False(result.IsComplete);
        using var pdf = new MemoryStream("%PDF-1.7\nstartxref\n0\n%%EOF"u8.ToArray());
        var document = await new FileContentClassifier().ClassifyAsync(pdf, ".pdf");
        Assert.Contains(FileContentFormat.Pdf, document.Formats);
        Assert.False(document.IsComplete);
    }

    [Fact]
    public async Task PngAndJpegRequireStructuralBoundariesRatherThanSignatureAlone()
    {
        var png = new byte[57];
        new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }.CopyTo(png, 0);
        BinaryPrimitives.WriteUInt32BigEndian(png.AsSpan(8), 13);
        "IHDR"u8.CopyTo(png.AsSpan(12));
        BinaryPrimitives.WriteUInt32BigEndian(png.AsSpan(16), 1);
        BinaryPrimitives.WriteUInt32BigEndian(png.AsSpan(20), 1);
        "IDAT"u8.CopyTo(png.AsSpan(37));
        "IEND"u8.CopyTo(png.AsSpan(49));
        using var source = new MemoryStream(png);
        var image = await new FileContentClassifier().ClassifyAsync(source, ".exe");
        Assert.Contains(FileContentFormat.Png, image.ValidatedFormats);
        Assert.True(image.HasExtensionMismatch);
        using var signatureOnly = new MemoryStream(png[..8]);
        Assert.False((await new FileContentClassifier().ClassifyAsync(signatureOnly, ".png")).IsComplete);

        byte[] jpeg = { 0xff, 0xd8, 0xff, 0xc0, 0, 8, 8, 0, 1, 0, 1, 0, 0xff, 0xda, 0, 6, 0, 0, 0, 0, 0xff, 0xd9 };
        using var compressed = new MemoryStream(jpeg);
        var photo = await new FileContentClassifier().ClassifyAsync(compressed, ".jpg");
        Assert.Contains(FileContentFormat.Jpeg, photo.ValidatedFormats);
        using var jpegOnly = new MemoryStream(jpeg[..3]);
        Assert.False((await new FileContentClassifier().ClassifyAsync(jpegOnly, ".jpg")).IsComplete);
    }

    [Fact]
    public async Task LargeTextSampleReportsUnidentifiedRemainder()
    {
        using var source = new MemoryStream(Enumerable.Repeat((byte)'a', 140000).ToArray());
        var result = await new FileContentClassifier().ClassifyAsync(source, ".txt");
        Assert.Contains(FileContentFormat.Text, result.Formats);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public async Task ScriptGrammarIsOnlyARoutingHintUnderAMediaName()
    {
        using var source = new MemoryStream("@echo off\necho harmless\n"u8.ToArray());
        var result = await new FileContentClassifier().ClassifyAsync(source, ".jpg");
        Assert.Contains(FileContentFormat.ScriptCandidate, result.Formats);
        Assert.True(result.HasExtensionMismatch);
        Assert.True(result.IsComplete);
    }

    [Fact]
    public async Task CancellationDoesNotLeaveStreamPositionChanged()
    {
        using var source = new MemoryStream(PeFixture());
        source.Position = 9;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new FileContentClassifier().ClassifyAsync(source, ".exe", cancellation.Token));
        Assert.Equal(9, source.Position);
    }

    [Theory]
    [InlineData("image.jpg")]
    [InlineData("archive")]
    public async Task ManualScannerPassesTypedZipIdentityToSharedCoordinator(string name)
    {
        using var zip = ZipFixture(("readme.txt", "harmless data"));
        string path = Path.Combine(_root, name);
        File.WriteAllBytes(path, zip.ToArray());
        var coordinator = new ContentCapture();
        var scanner = new FileScannerService(new DirectoryWalker(), new ScanQueueCoordinator(), new NoCache(), coordinator);
        var result = await scanner.ScanFileDetailedAsync(path, TimeSpan.FromSeconds(5));
        Assert.Equal(FileScanOutcome.Success, result.Outcome);
        Assert.True(result.ContentClassification?.RequiresZipInspection);
        Assert.True(coordinator.Classification?.RequiresZipInspection);
        Assert.NotNull(coordinator.ArchiveInspection);
        Assert.Null(result.Finding);
    }

    [Fact]
    public async Task RealtimeHubReceivesSameTypedDisguisedPeIdentity()
    {
        string path = Path.Combine(_root, "image.jpg");
        File.WriteAllBytes(path, PeFixture());
        var hub = new CaptureHub();
        var processor = new RealTimeVerdictProcessor(new HashService(), new Unsigned(), new NoRisk(), null, null, null, detectionHub: hub);
        var result = await processor.InspectFileAsync(path);
        Assert.Contains(FileContentFormat.PortableExecutable, result.ContentClassification!.ValidatedFormats);
        Assert.Same(result.ContentClassification, hub.Context!.ContentClassification);
        Assert.Same(hub.Context.ContentClassification, hub.Context.SharedScan!.ContentClassification);
    }

    /// <summary>Confirmed native evidence must survive a detector failure without claiming complete media inspection.</summary>
    [Fact]
    public async Task RealtimeConfirmedEvidence_PreservesIndependentDetectorCoverageFailure()
    {
        string path = Path.Combine(_root, "benign-pipeline-fixture.bin");
        File.WriteAllBytes(path, PeFixture());
        var hub = new CaptureHub
        {
            Result = new DetectionResult
            {
                Verdict = DetectionVerdict.ConfirmedMalicious, RiskScore = 100, IsComplete = false,
                FailedDetectorCount = 1, CoverageLimitations = ["SyntheticOptionalDetectorFailure"],
                Evidences = [new SecurityEvidence { Category = EvidenceCategory.AmsiProvider,
                    Confidence = EvidenceConfidence.Absolute, ScoreContribution = 100, Description = "Synthetic provider observation" }]
            }
        };
        var processor = new RealTimeVerdictProcessor(new HashService(), new Unsigned(), new NoRisk(), null, null, null, detectionHub: hub);
        var result = await processor.InspectFileAsync(path);
        Assert.Equal(RealTimeVerdict.ConfirmedMalicious, result.Verdict);
        Assert.Equal(RealTimePolicyAction.BlockAndQuarantine, result.RecommendedPolicy);
        Assert.False(result.InspectionComplete);
        Assert.Contains("SyntheticOptionalDetectorFailure", result.CoverageLimitations);
        Assert.True(result.ContentClassification!.IsComplete);
    }

    private static byte[] PeFixture()
    {
        var bytes = new byte[1024];
        bytes[0] = (byte)'M'; bytes[1] = (byte)'Z';
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 128);
        bytes[128] = (byte)'P'; bytes[129] = (byte)'E';
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(132), 0x14c);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(134), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(148), 224);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(150), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(152), 0x10b);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(152 + 60), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(152 + 224 + 16), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(152 + 224 + 20), 512);
        return bytes;
    }

    private static MemoryStream ZipFixture(params (string Name, string Content)[] members)
    {
        var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, true))
            foreach (var member in members)
            {
                using var writer = new StreamWriter(archive.CreateEntry(member.Name).Open(), new UTF8Encoding(false));
                writer.Write(member.Content);
            }
        stream.Position = 0;
        return stream;
    }

    private static int FindSignature(byte[] bytes, uint signature)
    {
        for (int i = 0; i <= bytes.Length - 4; i++)
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i)) == signature) return i;
        throw new InvalidDataException("Fixture signature missing.");
    }

    private sealed class ContentCapture : IPupAnalysisCoordinator
    {
        internal FileContentClassification? Classification { get; private set; }
        internal ArchiveScanResult? ArchiveInspection { get; private set; }
        public Task<SecurityFinding?> AnalyzeAsync(string path, FileInfo file, string hash, bool game, CancellationToken ct) => Task.FromResult<SecurityFinding?>(null);
        public Task<SecurityFinding?> AnalyzeContentAsync(string path, FileInfo file, string hash, FileContentClassification classification, ArchiveScanResult? archive, CancellationToken ct)
        { Classification = classification; ArchiveInspection = archive; return Task.FromResult<SecurityFinding?>(null); }
    }

    private sealed class CaptureHub : IDetectionHub
    {
        internal DetectionContext? Context { get; private set; }
        internal DetectionResult Result { get; init; } = new() { Verdict = DetectionVerdict.Clean };
        public int FailedDetectorCount => 0;
        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => Array.Empty<IDetectorPlugin>();
        public void RegisterDetector(IDetectorPlugin detector) { }
        public bool UnregisterDetector(string id) => false;
        public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken ct = default)
        { Context = context; return Task.FromResult(Result); }
    }

    private sealed class NoCache : IFileHashMatcher
    {
        public bool IsScanActive { get; set; }
        public Func<bool>? ActiveScanChecker { get; set; }
        public int CachedEntriesCount => 0;
        public int ScannedFromCache => 0;
        public int SkippedSignedClean => 0;
        public int NewlyScanned => 0;
        public void ResetCounters() { }
        public void ClearCache() { }
        public bool TryGetCached(string path, FileInfo info, bool game, out SecurityFinding? finding) { finding = null; return false; }
        public Task<(bool Hit, SecurityFinding? Finding, string? VerifiedHash)> TryGetCachedAsync(string path, FileInfo info, CancellationToken ct) => Task.FromResult((false, (SecurityFinding?)null, (string?)null));
        public Task<(string sha256, bool isAllowlisted, bool isMicrosoftBypassed)> EvaluateHashAndAllowlistAsync(string path, CancellationToken ct) => HashAsync(path, ct);
        public Task<(string sha256, bool isAllowlisted, bool isMicrosoftBypassed)> EvaluateHashAndAllowlistAsync(string path, CancellationToken ct, string? verifiedHash) => HashAsync(path, ct);
        private static async Task<(string, bool, bool)> HashAsync(string path, CancellationToken ct) => (await new HashService().ComputeSha256Async(path, ct), false, false);
        public void SetCache(string path, long size, DateTime modified, SecurityFinding? finding) { }
        public void SetCache(string path, long size, DateTime modified, SecurityFinding? finding, string? hash, bool allowed, bool signed) { }
        public void SetCache(string path, long size, DateTime modified, SecurityFinding? finding, string? hash, bool allowed, bool signed, long revision) { }
        public void InvalidateCache(string path) { }
    }

    private sealed class Unsigned : ISignatureVerifier
    { public Task<SignatureInfo> VerifySignatureAsync(string path, CancellationToken ct = default) => Task.FromResult(new SignatureInfo()); }
    private sealed class NoRisk : IRiskScoringEngine
    { public Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(FileAnalysisResult result, CancellationToken ct = default) => Task.FromResult((0, RiskLevel.Clean, new List<string>())); }

    /// <summary>Deletes only this test's explicitly created temporary fixture directory.</summary>
    public void Dispose() => Directory.Delete(_root, true);
}
