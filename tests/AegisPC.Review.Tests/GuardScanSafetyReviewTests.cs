using System.IO;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.AntiEvasion;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert evidence regressions using literal references and read-only operating-system files; never executes content or containment.</summary>
public sealed class GuardScanSafetyReviewTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "Ultron-GuardScan-" + Guid.NewGuid().ToString("N"));
    private string FilePath => Path.Combine(_directory, "fixture.dll");

    public GuardScanSafetyReviewTests()
    {
        Directory.CreateDirectory(_directory);
        File.WriteAllText(FilePath, "Benign reference fixture, not executable.");
    }

    [Theory]
    [InlineData("EtwEventWrite")]
    [InlineData("AmsiScanBuffer")]
    [InlineData("AmsiUtils")]
    [InlineData("amsiInitFailed")]
    public async Task LiteralReferences_AreCapability_NotExecutedTampering(string literal)
    {
        File.WriteAllText(FilePath, literal);
        var evaluation = new AntiEvasionDetector().AnalyzeBinary(FilePath);
        Assert.NotEmpty(evaluation.Evidences);
        Assert.All(evaluation.Evidences, e => Assert.Equal(EvidenceNature.Capability, e.Nature));
        Assert.All(evaluation.Evidences, e => Assert.NotEmpty(e.FeatureIdentity));
        var result = await new DetectionHub([new AntiEvasionDetectorPlugin()]).EvaluateAsync(new() { FilePath = FilePath });
        Assert.InRange(result.RiskScore, 0, 25);
        Assert.DoesNotContain(result.Verdict, new[] { DetectionVerdict.Suspicious, DetectionVerdict.HighRisk, DetectionVerdict.ConfirmedMalicious });
    }

    [Fact]
    public void OrdinarySyscallStub_IsNotAnExecutedBypass()
    {
        byte[] bytes = [0x4c, 0x8b, 0xd1, 0xb8, 0x18, 0, 0, 0, 0x0f, 0x05, 0xc3];
        var evaluation = new AntiEvasionDetector().AnalyzeBinary("inert.bin", bytes);
        Assert.Single(evaluation.Evidences);
        Assert.Equal(EvidenceNature.Capability, evaluation.Evidences[0].Nature);
        Assert.NotEmpty(evaluation.Evidences[0].FeatureIdentity);
    }

    /// <summary>Renaming content cannot disable bounded static observation.</summary>
    [Fact]
    public void RenamedReferenceFile_RetainsTheSameCapabilityEvidence()
    {
        string renamed = Path.Combine(_directory, "ordinary.jpg");
        File.WriteAllText(renamed, "EtwEventWrite");
        Assert.Equal("PE.Api.EtwEventWrite", Assert.Single(new AntiEvasionDetector().AnalyzeBinary(renamed).Evidences).FeatureIdentity);
    }

    /// <summary>Quoted API names in reported command text are not executed attack evidence.</summary>
    [Fact]
    public void CommandReferences_DoNotProveExecutedTampering()
    {
        var result = new AntiEvasionDetector().AnalyzeBehavior(0, "Write-Output 'AmsiUtils EtwEventWrite'");
        Assert.NotEmpty(result.Evidences);
        Assert.All(result.Evidences, e => Assert.Equal(EvidenceNature.Capability, e.Nature));
        Assert.All(result.Evidences, e => Assert.Equal(EvidenceConfidence.Low, e.Confidence));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnknownTrust_IsIncomplete_NotInvalidOrUnsigned(bool hasCertificate)
    {
        var verifier = new Verifier(new() { VerificationStatus = SignatureVerificationStatus.Unknown, IsSigned = hasCertificate });
        var context = new DetectionContext { FilePath = FilePath };
        var hub = new DetectionHub([new AuthenticodeDetector(verifier), new LocationReputationDetector(verifier)]);
        var result = await hub.EvaluateAsync(context);
        Assert.False(result.IsComplete);
        Assert.Contains(result.CoverageLimitations, l => l.Contains("SignatureVerificationUnavailable", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Evidences, e => e.FeatureIdentity == "PE.Unsigned" || e.RuleName == "Cert.InvalidSignature");
        Assert.Equal(DetectionVerdict.Unknown, result.Verdict);
    }

    [Theory]
    [InlineData(SignatureVerificationStatus.Valid)]
    [InlineData(SignatureVerificationStatus.Invalid)]
    [InlineData(SignatureVerificationStatus.Unsigned)]
    public async Task ExplicitTrustOutcome_PreservesItsMeaning(SignatureVerificationStatus status)
    {
        var verifier = new Verifier(new() { VerificationStatus = status, IsSigned = status != SignatureVerificationStatus.Unsigned,
            IsValid = status == SignatureVerificationStatus.Valid, Publisher = "Example Publisher" });
        var result = await new AuthenticodeDetector(verifier).EvaluateAsync(new() { FilePath = FilePath });
        Assert.NotEmpty(result);
        Assert.Equal(status == SignatureVerificationStatus.Valid, result.Any(e => e.TrustKind == EvidenceTrustKind.VerifiedAuthenticode));
        Assert.Equal(status == SignatureVerificationStatus.Invalid, result.Any(e => e.RuleName == "Cert.InvalidSignature"));
        Assert.Equal(status == SignatureVerificationStatus.Unsigned, result.Any(e => e.FeatureIdentity == "PE.Unsigned"));
    }

    [Theory]
    [InlineData("win32u.dll")]
    [InlineData("WS2_32.dll")]
    [InlineData("cryptbase.dll")]
    [InlineData("shlwapi.dll")]
    public async Task ActualWindowsBinaryReferences_StayBelowWarningThreshold(string name)
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name);
        Assert.True(File.Exists(path));
        var result = await new DetectionHub([new AntiEvasionDetectorPlugin()]).EvaluateAsync(new() { FilePath = path });
        Assert.InRange(result.RiskScore, 0, 25);
        Assert.All(result.Evidences, e => Assert.Equal(EvidenceNature.Capability, e.Nature));
        Assert.DoesNotContain(result.RecommendedPolicy, new[] { DetectionPolicy.Warn, DetectionPolicy.Quarantine, DetectionPolicy.BlockAndQuarantine });
    }

    private sealed class Verifier(SignatureInfo result) : ISignatureVerifier
    {
        public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default) => Task.FromResult(result);
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
