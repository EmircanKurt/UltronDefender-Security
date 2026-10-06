using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Runs the actual AMSI content plugin and hub with owned memory streams and result stubs; no native provider or Windows mutation.</summary>
public sealed class AmsiContentPipelineTests
{
    [Fact]
    public async Task NativeMalware_IsIndependentAuthorityDespiteSystemPathAndTrustMetadata()
    {
        var service = new InertService(Native(AmsiDetectionResult.Malicious, 32768, malicious: true));
        using var source = Text("param($x) Write-Output $x");
        source.Position = 4;
        var context = new DetectionContext { FilePath = @"C:\Windows\System32\renamed.png" };
        var plugin = new AmsiContentDetector(service);
        var hub = new DetectionHub(new IDetectorPlugin[] { new StreamDetector(plugin, source), new SupportingEvidence(0) });

        var result = await hub.EvaluateAsync(context);

        Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
        Assert.Equal(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
        Assert.Equal(100, result.RiskScore);
        Assert.Equal(1.0, result.ContextModifier);
        Assert.Equal(1, service.Calls);
        Assert.Equal(4, source.Position);
        Assert.True(source.CanRead);
        var providerEvidence = Assert.Single(result.Evidences.Where(e => e.Category == EvidenceCategory.AmsiProvider));
        Assert.Equal(EvidenceConfidence.Absolute, providerEvidence.Confidence);
        Assert.Equal("NativeProvider", providerEvidence.Metadata["VerdictSource"]);
        Assert.Contains(FileContentFormat.Text, context.ContentClassification!.Formats);
    }

    [Fact]
    public async Task AdministrativeProviderBlock_WarnsWithoutMalwareCertaintyOrQuarantine()
    {
        var service = new InertService(Native(AmsiDetectionResult.BlockedByAdmin, 16384));
        using var source = Text("Write-Output 'school policy fixture'");
        var result = await Hub(service, source).EvaluateAsync(Context());

        Assert.Equal(DetectionVerdict.Suspicious, result.Verdict);
        Assert.Equal(DetectionPolicy.Warn, result.RecommendedPolicy);
        Assert.Equal(50, result.RiskScore);
        Assert.Equal("Amsi.AdministrativePolicy", Assert.Single(result.Evidences).RuleName);
    }

    [Theory]
    [InlineData(AmsiVerdictSource.HeuristicFallback)]
    [InlineData(AmsiVerdictSource.CanonicalTestSignature)]
    public async Task LocalFallbackMaliciousFlag_CannotImpersonateNativeProviderAuthority(AmsiVerdictSource sourceKind)
    {
        var fallback = new AmsiScanResult
        {
            IsMalicious = true, Result = AmsiDetectionResult.Malicious, Source = sourceKind,
            NativeStatus = AmsiNativeScanStatus.Unavailable, IsComplete = false, RawResultCode = 32768,
            HeuristicIndicators = AmsiHeuristicIndicators.DefenseEvasionReference
        };
        using var source = Text("Documentation references amsiInitFailed");
        var result = await Hub(new InertService(fallback), source).EvaluateAsync(Context());

        Assert.Equal(DetectionVerdict.Unknown, result.Verdict);
        Assert.Equal(DetectionPolicy.Observe, result.RecommendedPolicy);
        Assert.False(result.IsComplete);
        Assert.Equal(0, result.RiskScore);
        Assert.All(result.Evidences, evidence => Assert.NotEqual(EvidenceConfidence.Absolute, evidence.Confidence));
        Assert.NotEmpty(result.CoverageLimitations);
    }

    [Theory]
    [InlineData(AmsiDetectionResult.Malicious, 0, true)]
    [InlineData(AmsiDetectionResult.Malicious, 32768, false)]
    [InlineData(AmsiDetectionResult.Clean, 32768, false)]
    [InlineData(AmsiDetectionResult.NotDetected, 16384, false)]
    [InlineData(AmsiDetectionResult.Clean, -1, false)]
    public async Task InconsistentProviderFields_AreUnknownNotAuthoritative(AmsiDetectionResult verdict, int raw, bool malicious)
    {
        using var source = Text("synthetic provider consistency fixture");
        var result = await Hub(new InertService(Native(verdict, raw, malicious)), source).EvaluateAsync(Context());

        Assert.Equal(DetectionVerdict.Unknown, result.Verdict);
        Assert.Equal(0, result.RiskScore);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public async Task ProviderClean_DoesNotEraseOtherDetectorsPositiveEvidence()
    {
        using var source = Text("Write-Output 'provider-clean fixture'");
        var content = new StreamDetector(new AmsiContentDetector(new InertService(Native(AmsiDetectionResult.Clean, 0))), source);
        var result = await new DetectionHub(new IDetectorPlugin[] { content, new SupportingEvidence(40) }).EvaluateAsync(Context());

        Assert.Equal(40, result.RiskScore);
        Assert.Equal(DetectionVerdict.LowRisk, result.Verdict);
        Assert.Equal(2, result.Evidences.Count);
        Assert.Equal(0, result.Evidences.Single(e => e.Category == EvidenceCategory.AmsiProvider).ScoreContribution);
    }

    [Fact]
    public async Task BinaryStructure_IsExplicitlyNotApplicableAndNeverSentToTextProvider()
    {
        var service = new InertService(Native(AmsiDetectionResult.Malicious, 32768, true));
        var classification = new FileContentClassification();
        classification.Formats.Add(FileContentFormat.PortableExecutable);
        classification.ValidatedFormats.Add(FileContentFormat.PortableExecutable);
        var context = new DetectionContext { ContentClassification = classification, FilePath = "inert:binary" };
        using var source = new MemoryStream(new byte[] { 0x4d, 0x5a, 0x00, 0xff });

        var evidence = Assert.Single(await new AmsiContentDetector(service).EvaluateContentAsync(context, source));

        Assert.Equal(0, service.Calls);
        Assert.Equal(0, evidence.ScoreContribution);
        Assert.Equal("Amsi.NotApplicable", evidence.RuleName);
        Assert.DoesNotContain("clean", evidence.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SharedTypedBinaryClassification_DoesNotOpenAnInapplicableSource()
    {
        var classification = new FileContentClassification();
        classification.Formats.Add(FileContentFormat.PortableExecutable);
        classification.ValidatedFormats.Add(FileContentFormat.PortableExecutable);
        string absentPath = Path.Combine(Path.GetTempPath(), "Ultron_Amsi_NoRead_" + Guid.NewGuid().ToString("N") + ".exe");
        Assert.False(File.Exists(absentPath));
        var context = new DetectionContext
        {
            FilePath = absentPath,
            SharedScan = new ScanContext(absentPath) { ContentClassification = classification }
        };
        var service = new InertService(Native(AmsiDetectionResult.Malicious, 32768, true));

        var evidence = Assert.Single(await new AmsiContentDetector(service).EvaluateAsync(context));

        Assert.Equal("Amsi.NotApplicable", evidence.RuleName);
        Assert.Equal(0, service.Calls);
        Assert.Empty(context.CoverageLimitations); // Opening the absent path would instead report an I/O coverage gap.
        Assert.False(File.Exists(absentPath));
    }

    [Fact]
    public async Task OversizedText_IsExplicitCoverageGapWithoutPartialProviderCleanClaim()
    {
        var service = new InertService(Native(AmsiDetectionResult.Clean, 0));
        using var source = new MemoryStream(new byte[1024 * 1024 + 1]);
        source.Position = 17;
        var context = Context();
        var result = await Hub(service, source).EvaluateAsync(context);

        Assert.Equal(0, service.Calls);
        Assert.Equal(17, source.Position);
        Assert.Equal(DetectionVerdict.Unknown, result.Verdict);
        Assert.False(result.IsComplete);
        Assert.Contains(result.CoverageLimitations, limitation => limitation.Contains("1 MiB", StringComparison.Ordinal));
    }

    [Fact]
    public async Task InvalidUtf8_CannotBeSilentlyReplacedAndReportedInspected()
    {
        var service = new InertService(Native(AmsiDetectionResult.Clean, 0));
        using var source = new MemoryStream(new byte[] { 0xc3, 0x28 });
        source.Position = 1;
        var result = await Hub(service, source).EvaluateAsync(Context());

        Assert.Equal(0, service.Calls);
        Assert.Equal(1, source.Position);
        Assert.Equal(DetectionVerdict.Unknown, result.Verdict);
        Assert.Contains(result.CoverageLimitations, limitation => limitation.Contains("strictly decode", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BomMarkedUtf16_IsStrictlyDecodedAndEntireTextInspected(bool bigEndian)
    {
        const string input = "Write-Output 'öğrenci π'";
        var encoding = new UnicodeEncoding(bigEndian, true, true);
        using var source = new MemoryStream(encoding.GetPreamble().Concat(encoding.GetBytes(input)).ToArray());
        source.Position = 1;
        var service = new InertService(Native(AmsiDetectionResult.NotDetected, 1));
        var context = Context(sharedOnly: true);

        var result = await Hub(service, source).EvaluateAsync(context);

        Assert.True(result.IsComplete);
        Assert.Equal(input, service.LastContent);
        Assert.Equal(1, service.Calls);
        Assert.Equal(1, source.Position);
    }

    [Fact]
    public async Task CancellationWhileAwaitingProvider_RestoresCallerStreamAndDoesNotPublishResult()
    {
        var pending = new TaskCompletionSource<AmsiScanResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new InertService(pending.Task);
        using var source = Text("Write-Output 'cancelled fixture'");
        source.Position = 7;
        using var cancellation = new CancellationTokenSource();
        var inspection = new AmsiContentDetector(service).EvaluateContentAsync(Context(), source, cancellation.Token);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => inspection);
        Assert.Equal(1, service.Calls);
        Assert.Equal(7, source.Position);
        Assert.True(source.CanRead);
    }

    private static MemoryStream Text(string text) => new(Encoding.UTF8.GetBytes(text));
    private static DetectionContext Context(bool sharedOnly = false)
    {
        var classification = new FileContentClassification();
        classification.Formats.Add(FileContentFormat.Text);
        return new DetectionContext
        {
            FilePath = "inert:script-content",
            ContentClassification = sharedOnly ? null : classification,
            SharedScan = new ScanContext("inert:script-content") { ContentClassification = classification }
        };
    }
    private static DetectionHub Hub(IAmsiScanService service, Stream source) =>
        new(new[] { new StreamDetector(new AmsiContentDetector(service), source) });
    private static AmsiScanResult Native(AmsiDetectionResult result, int raw, bool malicious = false) => new()
    {
        Result = result, RawResultCode = raw, IsMalicious = malicious, Source = AmsiVerdictSource.NativeProvider,
        NativeStatus = AmsiNativeScanStatus.Completed, NativeHResult = 0, IsComplete = true
    };

    private sealed class InertService : IAmsiScanService
    {
        private readonly Task<AmsiScanResult> _result;
        public InertService(AmsiScanResult result) : this(Task.FromResult(result)) { }
        public InertService(Task<AmsiScanResult> result) { _result = result; }
        public int Calls { get; private set; }
        public string? LastContent { get; private set; }
        public bool IsAmsiSupported => true;
        public Task<AmsiScanResult> ScanStringAsync(string content, string contentName = "DynamicScript")
        { Calls++; LastContent = content; return _result; }
        public Task<AmsiScanResult> ScanBufferAsync(byte[] buffer, string contentName = "MemoryBuffer") => throw new NotSupportedException();
        public void Dispose() { }
    }

    private sealed class StreamDetector : IDetectorPlugin
    {
        private readonly AmsiContentDetector _plugin;
        private readonly Stream _source;
        public StreamDetector(AmsiContentDetector plugin, Stream source) { _plugin = plugin; _source = source; }
        public string DetectorId => _plugin.DetectorId;
        public string DisplayName => _plugin.DisplayName;
        public EvidenceCategory PrimaryCategory => _plugin.PrimaryCategory;
        public int Priority => _plugin.Priority;
        public bool IsEnabled { get; set; } = true;
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
            => _plugin.EvaluateContentAsync(context, _source, cancellationToken);
    }

    private sealed class SupportingEvidence : IDetectorPlugin
    {
        private readonly int _score;
        public SupportingEvidence(int score) { _score = score; }
        public string DetectorId => "inert:independent-evidence";
        public string DisplayName => DetectorId;
        public EvidenceCategory PrimaryCategory => _score > 0 ? EvidenceCategory.StaticApi : EvidenceCategory.DigitalCertificate;
        public int Priority => 1;
        public bool IsEnabled { get; set; } = true;
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
            => Task.FromResult<IEnumerable<SecurityEvidence>>(new[]
            {
                new SecurityEvidence
                {
                    SourceDetector = DetectorId, Category = PrimaryCategory, ScoreContribution = _score,
                    Confidence = _score > 0 ? EvidenceConfidence.High : EvidenceConfidence.Absolute,
                    RuleName = "ValidMicrosoft.TrustedPublisher", TrustKind = _score == 0 ? EvidenceTrustKind.VerifiedOsAuthenticode : EvidenceTrustKind.None
                }
            });
    }
}
