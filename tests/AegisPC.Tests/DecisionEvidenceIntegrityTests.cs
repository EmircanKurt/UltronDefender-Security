using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert decision regressions: no native calls, real malware, registry, process, service, or vault actions.</summary>
[Collection("SequentialDiskTests")]
public sealed class DecisionEvidenceIntegrityTests
{
    [Theory]
    [InlineData(SystemPersistenceObservationKind.DebuggerRedirect, @"C:\Tools\debugger.exe")]
    [InlineData(SystemPersistenceObservationKind.DesktopShell, @"C:\School\kiosk.exe")]
    [InlineData(SystemPersistenceObservationKind.LogonInitializer, "userinit.exe, school-logon.exe,")]
    [InlineData(SystemPersistenceObservationKind.GlobalLibraryLoad, @"C:\Tools\assistive-library.dll")]
    [InlineData(SystemPersistenceObservationKind.Autorun, "powershell.exe -enc school-script")]
    [InlineData(SystemPersistenceObservationKind.ServiceLibrary, @"C:\Users\student\AppData\Local\service.dll")]
    [InlineData(SystemPersistenceObservationKind.ScheduledCommand, "powershell.exe -EncodedCommand admin-script")]
    [InlineData(SystemPersistenceObservationKind.SecurityDomainRedirect, "0.0.0.0 updates.vendor.example")]
    [InlineData(SystemPersistenceObservationKind.TemporaryProcess, @"C:\Users\student\Temp\installer.exe")]
    public void PersistenceConfigurationHint_CannotEstablishConfirmedMalware(
        SystemPersistenceObservationKind kind, string value)
    {
        var finding = SystemPersistenceEvidenceClassifier.Evaluate(new SystemPersistenceObservation
        {
            Kind = kind, Value = value, ObjectPath = "inert:configuration", ObjectName = "review fixture"
        });

        Assert.NotNull(finding);
        Assert.InRange(finding!.RiskScore, 1, 60);
        Assert.NotEqual(RiskLevel.ConfirmedMalicious, finding.RiskLevel);
        Assert.NotEqual(RiskLevel.HighRisk, finding.RiskLevel);
        Assert.Contains("doğrulanmadı", finding.Description);
        Assert.Contains(finding.RiskReasons, reason => reason.Contains("otomatik karantina", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(SystemPersistenceObservationKind.DesktopShell, "explorer.exe")]
    [InlineData(SystemPersistenceObservationKind.LogonInitializer, "userinit.exe,")]
    [InlineData(SystemPersistenceObservationKind.ServiceLibrary, @"C:\Program Files\School\service.dll")]
    [InlineData(SystemPersistenceObservationKind.Autorun, @"C:\Program Files\School\sync.exe")]
    [InlineData(SystemPersistenceObservationKind.ScheduledCommand, "powershell.exe -File backup.ps1")]
    [InlineData(SystemPersistenceObservationKind.TemporaryProcess, @"C:\Program Files\School\tool.exe")]
    public void OrdinaryPersistenceSnapshot_DoesNotProduceAnUnsupportedThreat(
        SystemPersistenceObservationKind kind, string value)
    {
        Assert.Null(SystemPersistenceEvidenceClassifier.Evaluate(new SystemPersistenceObservation
        {
            Kind = kind, Value = value
        }));
    }

    [Fact]
    public void PersistenceReadFailure_IsExplicitUnknownCoverage()
    {
        var finding = SystemPersistenceEvidenceClassifier.Evaluate(new SystemPersistenceObservation
        {
            Kind = SystemPersistenceObservationKind.CoverageGap, Value = "Source could not be read."
        });

        Assert.NotNull(finding);
        Assert.Equal(RiskLevel.Unknown, finding!.RiskLevel);
        Assert.Equal(0, finding.RiskScore);
        Assert.Equal(ConfidenceLevel.Low, finding.ConfidenceLevel);
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\test.exe")]
    [InlineData(@"C:\Users\student\node_modules\test.exe")]
    [InlineData(@"C:\Users\student\Games\test.exe")]
    public async Task RuleNamePathAndTypedTrust_CannotEraseIndependentPositiveEvidence(string path)
    {
        var hub = Hub(
            Evidence("trust", EvidenceCategory.DigitalCertificate, 0, "ValidMicrosoft.TrustedPublisher",
                confidence: EvidenceConfidence.Absolute, trust: EvidenceTrustKind.VerifiedOsAuthenticode),
            Evidence("api", EvidenceCategory.StaticApi, 45),
            Evidence("entropy", EvidenceCategory.EntropyAnomaly, 35),
            Evidence("evasion", EvidenceCategory.AntiEvasion, 40));

        var result = await hub.EvaluateAsync(new DetectionContext { FilePath = path });

        Assert.Equal(100, result.RiskScore);
        Assert.Equal(1.0, result.ContextModifier);
        Assert.Equal(DetectionVerdict.HighRisk, result.Verdict);
        Assert.Equal(DetectionPolicy.Warn, result.RecommendedPolicy);
        Assert.Equal(EvidenceConfidence.Medium, result.OverallConfidence);
        Assert.Equal(EvidenceTrustKind.VerifiedOsAuthenticode, result.Evidences.Single(e => e.SourceDetector == "trust").TrustKind);
    }

    [Fact]
    public async Task NegativeReputationScore_CannotErasePositiveEvidenceInSameCorrelationGroup()
    {
        var hub = Hub(
            Evidence("positive", EvidenceCategory.StaticApi, 45, group: "shared"),
            Evidence("reputation", EvidenceCategory.StaticApi, -100, group: "shared", trust: EvidenceTrustKind.KnownTrustedHash));

        var result = await hub.EvaluateAsync(new DetectionContext { FilePath = "inert:sample" });

        Assert.Equal(45, result.RiskScore);
        Assert.Equal(45, result.RawScore);
        Assert.Equal(45, result.DeduplicatedScore);
        Assert.Equal(2, result.Evidences.Count);
        Assert.Contains("-100", result.ScoreTrace);
    }

    [Fact]
    public async Task SameDisplayRuleAndGroup_InIndependentCategories_AreNotLost()
    {
        var hub = Hub(
            Evidence("detector-a", EvidenceCategory.StaticApi, 45, "shared-rule", "shared-group"),
            Evidence("detector-b", EvidenceCategory.Persistence, 30, "shared-rule", "shared-group"));

        var result = await hub.EvaluateAsync(new DetectionContext { FilePath = "inert:sample" });

        Assert.Equal(75, result.RiskScore);
        Assert.Equal(2, result.Evidences.Count);
    }

    [Fact]
    public async Task AbsoluteSignature_RemainsAuthoritativeDespiteTrustAndCoverageGaps()
    {
        var hub = Hub(
            Evidence("signature", EvidenceCategory.StaticSignature, 100, confidence: EvidenceConfidence.Absolute),
            Evidence("trust", EvidenceCategory.DigitalCertificate, -100, "ValidMicrosoft", trust: EvidenceTrustKind.KnownTrustedHash));
        var context = new DetectionContext { FilePath = @"C:\Windows\System32\sample.exe" };
        context.CoverageLimitations.Add("An unrelated format could not be inspected.");

        var result = await hub.EvaluateAsync(context);

        Assert.Equal(100, result.RiskScore);
        Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
        Assert.Equal(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public async Task ZeroScoreTrustAndDetectorFailure_CannotEstablishCleanCoverage()
    {
        var hub = Hub(Evidence("trust", EvidenceCategory.DigitalCertificate, 0,
            confidence: EvidenceConfidence.Absolute, trust: EvidenceTrustKind.VerifiedAuthenticode));
        hub.RegisterDetector(new InertDetector("failure", Array.Empty<SecurityEvidence>(), fail: true));

        var result = await hub.EvaluateAsync(new DetectionContext { FilePath = "inert:sample" });

        Assert.Equal(DetectionVerdict.Unknown, result.Verdict);
        Assert.Equal(DetectionPolicy.Observe, result.RecommendedPolicy);
        Assert.False(result.IsComplete);
        Assert.Equal(1, result.FailedDetectorCount);
        Assert.Equal(EvidenceConfidence.Low, result.OverallConfidence);
    }

    [Fact]
    public async Task UnsignedLoadedFeedHash_CannotForgeConfirmedDetectionAndDoesNotInitializeStorage()
    {
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("inert loaded feed exclusion fixture")));
        var table = (ConcurrentDictionary<string, (string Name, string Category, int Severity)>)typeof(ThreatSignatureDatabase)
            .GetField("_memoryCache", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
        var initialized = typeof(ThreatSignatureDatabase).GetField("_isInitialized", BindingFlags.NonPublic | BindingFlags.Static)!;
        bool beforeInitialized = (bool)initialized.GetValue(null)!;
        string beforePath = ThreatSignatureDatabase.CurrentDbPath;
        bool hadPrevious = table.TryGetValue(hash, out var previous);
        table[hash] = ("Inert memory-only decision fixture", "Test", 100);
        try
        {
            Assert.False(ThreatSignatureDatabase.TryCheckLoadedHash(hash, out _));
            Assert.True(ThreatSignatureDatabase.TryGetUnverifiedMetadata(hash, out _));
            Assert.False(MalwareSignatureDatabase.HasLoadedHash(hash));
            var exclusions = new ExcludesEverything();
            var detector = new InertDetector("fixture", new[]
            {
                Evidence("fixture", EvidenceCategory.StaticSignature, 100, confidence: EvidenceConfidence.Absolute)
            });
            var result = await new DetectionHub(new[] { detector }, exclusionService: exclusions)
                .EvaluateAsync(new DetectionContext { FilePath = "inert:excluded-feed-fixture", SHA256 = hash });

            Assert.NotEqual(DetectionVerdict.ConfirmedMalicious, result.Verdict);
            Assert.Equal(1, exclusions.Calls);
            Assert.Equal(beforePath, ThreatSignatureDatabase.CurrentDbPath);
            Assert.Equal(beforeInitialized, (bool)initialized.GetValue(null)!);
        }
        finally
        {
            if (hadPrevious) table[hash] = previous;
            else table.TryRemove(hash, out _);
        }
    }

    [Fact]
    public void LoadedFeedReadOnlyGate_InvalidHashesCannotInitializeStorage()
    {
        var initialized = typeof(ThreatSignatureDatabase).GetField("_isInitialized", BindingFlags.NonPublic | BindingFlags.Static)!;
        bool before = (bool)initialized.GetValue(null)!;
        string beforePath = ThreatSignatureDatabase.CurrentDbPath;
        foreach (string? hash in new string?[] { null, string.Empty, new('a', 32), new('z', 64) })
        {
            Assert.False(ThreatSignatureDatabase.TryCheckLoadedHash(hash, out _));
            Assert.False(MalwareSignatureDatabase.HasLoadedHash(hash));
        }
        Assert.Equal(before, (bool)initialized.GetValue(null)!);
        Assert.Equal(beforePath, ThreatSignatureDatabase.CurrentDbPath);
    }

    private static DetectionHub Hub(params SecurityEvidence[] evidence) =>
        new(new[] { new InertDetector("fixture", evidence) });

    private static SecurityEvidence Evidence(string source, EvidenceCategory category, int score,
        string rule = "fixture-rule", string group = "fixture-group",
        EvidenceConfidence confidence = EvidenceConfidence.Medium, EvidenceTrustKind trust = EvidenceTrustKind.None) => new()
        {
            SourceDetector = source, Category = category, ScoreContribution = score,
            RuleName = rule, CorrelationGroup = group, Confidence = confidence, TrustKind = trust,
            FilePath = "inert:sample", Description = "Synthetic evidence; no malware efficacy measurement."
        };

    private sealed class InertDetector : IDetectorPlugin
    {
        private readonly IEnumerable<SecurityEvidence> _evidence;
        private readonly bool _fail;
        public InertDetector(string id, IEnumerable<SecurityEvidence> evidence, bool fail = false)
        { DetectorId = id; _evidence = evidence; _fail = fail; }
        public string DetectorId { get; }
        public string DisplayName => DetectorId;
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticApi;
        public int Priority => 10;
        public bool IsEnabled { get; set; } = true;
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_fail) throw new IOException("Synthetic inspection failure.");
            return Task.FromResult(_evidence);
        }
    }

    private sealed class ExcludesEverything : AegisPC.Contracts.Services.IExclusionService
    {
        public int Calls { get; private set; }
        public bool IsExcluded(string? filePath, string? sha256 = null) { Calls++; return true; }
        public Task<bool> IsExcludedAsync(string? filePath, string? sha256 = null, CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task<IReadOnlyList<ExclusionEntry>> GetAllExclusionsAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<ExclusionEntry> AddPathExclusionAsync(string path, bool includeSubdirectories = true, string? reason = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<ExclusionEntry> AddSha256ExclusionAsync(string sha256, string? reason = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public void AddTemporaryPathExclusion(string path, TimeSpan duration, string? reason = null) => throw new NotSupportedException();
        public Task<bool> RemoveExclusionAsync(int id, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public bool IsRootOrSystemDirectory(string path) => false;
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
