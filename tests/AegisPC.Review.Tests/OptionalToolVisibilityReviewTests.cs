using System.Text.Json;
using System.IO;
using AegisPC.App.ViewModels;
using AegisPC.Infrastructure.Configuration;
using AegisPC.ServiceContracts;
using AegisPC.Security.Scanning;
using AegisPC.Security;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.ServiceContracts.IpcMessages;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Typed decision/visibility fixtures, no live catalog, host setting, malware or remediation.</summary>
public sealed class OptionalToolVisibilityReviewTests
{
    private const string Hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    internal static SecurityFinding Tool() => new()
    {
        SoftwareClass = SoftwareFindingClass.PotentiallyUnwantedToolOnly, SHA256 = Hash,
        RuleSetVersion = DetectionRuleSet.Version, InspectionComplete = true, RiskLevel = RiskLevel.LowRisk,
        SoftwareClassification = new() { Verified = true, SHA256 = Hash, SourceReference = "https://example.test/tool", IntelVersion = "inert-v1", ValidUntilUtc = DateTime.UtcNow.AddDays(1) }
    };

    /// <summary>Visibility never mutates raw data or allows an optional label to authorize a malware score.</summary>
    [Fact]
    public async Task PureToolHiddenByDefaultButMixedEvidenceAlwaysVisible()
    {
        var tool = Tool();
        Assert.False(FindingVisibilityPolicy.IsVisible(tool));
        Assert.True(FindingVisibilityPolicy.IsVisible(tool, true));
        Assert.False(FindingVisibilityPolicy.IsSecurityConcern(tool));
        var label = GameModEvidenceReviewTests.Item("optional", EvidenceCategory.StaticSignature, EvidenceNature.SoftwareClassification, 100);
        label.OptionalToolClassification = tool.SoftwareClassification;
        var hub = new DetectionHub([new GameModEvidenceReviewTests.FixtureDetector([label])]);
        var result = await hub.EvaluateAsync(new DetectionContext { SHA256 = Hash });
        Assert.Equal(0, result.RiskScore); Assert.Equal(DetectionPolicy.Allow, result.RecommendedPolicy);
        Assert.Equal(SoftwareFindingClass.PotentiallyUnwantedToolOnly, result.SoftwareClass);
        var exact = GameModEvidenceReviewTests.Item("independent", EvidenceCategory.StaticSignature, EvidenceNature.Authoritative, 100);
        exact.Confidence = EvidenceConfidence.Absolute;
        result = await new DetectionHub([new GameModEvidenceReviewTests.FixtureDetector([label, exact])]).EvaluateAsync(new DetectionContext { SHA256 = Hash });
        Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
        Assert.Equal(SoftwareFindingClass.MalwareConcern, result.SoftwareClass);
        Assert.Equal(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
    }

    /// <summary>Incomplete, stale, excluded, invalid-provenance, mixed and legacy records cannot disappear.</summary>
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)] [InlineData(8)]
    public void IneligibleRecordAlwaysVisible(int mutation)
    {
        var f = Tool();
        switch (mutation)
        {
            case 0: f.InspectionComplete = false; break;
            case 1: f.RuleSetVersion = "old"; break;
            case 2: f.IsAllowlisted = true; break;
            case 3: f.HasIndependentMalwareEvidence = true; break;
            case 4: f.SoftwareClassification!.Verified = false; break;
            case 5: f.SHA256 = new string('B', 64); break;
            case 6: f.SoftwareClassification!.ValidUntilUtc = DateTime.UtcNow.AddMinutes(-1); break;
            case 7: f.CoverageLimitations.Add("timeout"); break;
            case 8: f.RiskLevel = RiskLevel.Unknown; break;
        }
        Assert.True(FindingVisibilityPolicy.IsVisible(f));
        Assert.True(FindingVisibilityPolicy.IsVisible(JsonSerializer.Deserialize<SecurityFinding>(JsonSerializer.Serialize(f))!));
    }

    /// <summary>Absent additive fields default safe across legacy persistence and IPC.</summary>
    [Fact]
    public void OldRecordsCannotBeRetypedByCategoryOrText()
    {
        var legacy = JsonSerializer.Deserialize<SecurityFinding>("{\"Title\":\"PUA HackTool\",\"Category\":12}")!;
        Assert.Equal(SoftwareFindingClass.Unclassified, legacy.SoftwareClass);
        Assert.True(FindingVisibilityPolicy.IsVisible(legacy));
        var ipc = JsonSerializer.Deserialize<ThreatNotification>("{\"FilePath\":\"x\",\"ProcessName\":\"x\",\"ThreatName\":\"PUA\",\"ActionTaken\":\"recorded\",\"Details\":\"x\"}")!;
        Assert.False(ipc.InspectionComplete); Assert.Equal(SoftwareFindingClass.Unclassified, ipc.SoftwareClass);
        Assert.Equal(0, (int)SoftwareFindingClass.Unclassified);
        Assert.Equal(1, (int)SoftwareFindingClass.PotentiallyUnwantedToolOnly);
        Assert.Equal(2, (int)SoftwareFindingClass.MalwareConcern);
    }

    /// <summary>The actual settings view model saves only local visibility, not service protection commands.</summary>
    [Fact]
    public async Task VisibilityToggleDoesNotSendServicePolicy()
    {
        string root = Path.Combine(Path.GetTempPath(), "Ultron-Visibility-" + Guid.NewGuid().ToString("N"));
        var settings = new SettingsService(Path.Combine(root, "settings.json"));
        using var ipc = new InertIpc();
        using var view = new SettingsViewModel(settingsService: settings, ipcClient: ipc);
        int before = ipc.Commands;
        long revision = DetectionPolicyRevision.Current;
        view.ShowPotentiallyUnwantedToolFindings = true;
        for (int i = 0; i < 200 && !view.StatusMessage.Contains("görünürlüğü kaydedildi", StringComparison.Ordinal); i++) await Task.Delay(10);
        Assert.Contains("görünürlüğü kaydedildi", view.StatusMessage);
        Assert.Equal(before, ipc.Commands); Assert.Equal(revision, DetectionPolicyRevision.Current);
        var reloaded = new SettingsService(Path.Combine(root, "settings.json")); await reloaded.LoadAsync();
        Assert.True(reloaded.Current.ShowPotentiallyUnwantedToolFindings);
        Assert.True(reloaded.Current.IsFileProtectionEnabled);
    }

    /// <summary>The actual manual-scan adapter cannot promote even an Absolute informational label to malware.</summary>
    [Fact]
    public async Task ManualAdapterRetainsInformationalClass()
    {
        string path = Path.Combine(Path.GetTempPath(), "Ultron-Informational-" + Guid.NewGuid().ToString("N") + ".txt");
        await File.WriteAllTextAsync(path, "Inert decision fixture only.");
        var label = GameModEvidenceReviewTests.Item("tool", EvidenceCategory.StaticSignature, EvidenceNature.SoftwareClassification, 100);
        label.Confidence = EvidenceConfidence.Absolute; label.OptionalToolClassification = Tool().SoftwareClassification;
        var hub = new DetectionHub([new GameModEvidenceReviewTests.FixtureDetector([label])]);
        var finding = await new PupAnalysisCoordinator(hub).AnalyzeAsync(path, new FileInfo(path), Hash, false, CancellationToken.None);
        Assert.NotNull(finding); Assert.Equal(0, finding!.RiskScore); Assert.Equal(RiskLevel.LowRisk, finding.RiskLevel);
        Assert.Equal(FindingCategory.PotentiallyUnwantedProgram, finding.Category);
        Assert.False(FindingVisibilityPolicy.IsVisible(finding));
    }

    private sealed class InertIpc : IServiceIpcClient
    {
        internal int Commands;
        public bool IsConnected => true;
        public event Action<ThreatNotification>? ThreatDetected { add { } remove { } }
        public event Action<ProtectionStatus>? StatusChanged { add { } remove { } }
        public Task ConnectAsync() => Task.CompletedTask;
        public Task SendCommandAsync(ServiceCommand command) { Commands++; return Task.CompletedTask; }
        public Task<ProtectionStatus> GetStatusAsync() => Task.FromResult(new ProtectionStatus { ProtectionLevel = "Inert fixture" });
        public void Dispose() { }
    }
}
