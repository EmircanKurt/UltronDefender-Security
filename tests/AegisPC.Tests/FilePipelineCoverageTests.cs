using System.Text.Json;
using System.IO;
using System.Text.Json.Nodes;
using AegisPC.App.Services;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Uses only synthetic detector observations and temporary report files; no native provider or malware is invoked.</summary>
public sealed class FilePipelineCoverageTests
{
    /// <summary>Confirmed evidence remains actionable while another detector's missing coverage remains visible.</summary>
    [Fact]
    public async Task ConfirmedFinding_DoesNotHideDetectorFailure()
    {
        var coordinator = new PupAnalysisCoordinator(new FakeHub(new DetectionResult
        {
            Verdict = DetectionVerdict.ConfirmedMalicious, RiskScore = 100, IsComplete = false,
            FailedDetectorCount = 1, CoverageLimitations = ["ScriptProviderUnavailable"],
            Evidences = [new SecurityEvidence { Category = EvidenceCategory.StaticSignature,
                Confidence = EvidenceConfidence.Absolute, ScoreContribution = 100, Description = "Synthetic verified evidence" }]
        }));
        string file = typeof(FilePipelineCoverageTests).Assembly.Location;
        var result = await coordinator.AnalyzeContentDetailedAsync(file, new FileInfo(file), new string('A', 64), new(), null, default);
        Assert.Equal(RiskLevel.ConfirmedMalicious, result.Finding?.RiskLevel);
        Assert.False(result.IsComplete);
        Assert.Contains("ScriptProviderUnavailable", result.CoverageLimitations);
        Assert.Contains("DetectorExecutionFailed", result.CoverageLimitations);
    }

    /// <summary>A successful detector subset does not establish cleanliness when structure inspection was partial.</summary>
    [Fact]
    public async Task PartialClassification_IsNotCleanSuccess()
    {
        var coordinator = new PupAnalysisCoordinator(new FakeHub(new DetectionResult { IsComplete = true }));
        var classification = new FileContentClassification { Coverage = ContentClassificationCoverage.Partial };
        classification.CoverageLimitations.Add("AmbiguousContent");
        string file = typeof(FilePipelineCoverageTests).Assembly.Location;
        var result = await coordinator.AnalyzeContentDetailedAsync(file, new FileInfo(file), new string('B', 64), classification, null, default);
        Assert.Null(result.Finding); Assert.False(result.IsComplete);
        Assert.Contains("AmbiguousContent", result.CoverageLimitations);
    }

    /// <summary>Full-scan traversal consumes resolved volume roots once and retains readiness gaps.</summary>
    [Fact]
    public async Task FullScan_UsesVolumeTargetsAndPreservesInventoryGaps()
    {
        string root = Path.Combine(Path.GetTempPath(), "AegisVolumeTargets_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string file = Path.Combine(root, "readme.txt"); await File.WriteAllTextAsync(file, "Inert volume fixture.");
            var coverage = new ScanCoverageSummary();
            var walker = new DirectoryWalker(volumeTargets: new FakeVolumes(root));
            using var scope = walker.BeginCoverage(coverage);
            var queued = new List<string>();
            await walker.WalkDirectoriesForScanTypeAsync(ScanType.Full, null, p => { queued.Add(p); return Task.CompletedTask; }, _ => { }, default);
            Assert.Equal(file, Assert.Single(queued)); Assert.False(coverage.IsComplete);
            Assert.Contains("LocalVolumeNotReadyOrAccessible", coverage.Limitations);
        }
        finally { Directory.Delete(root, true); }
    }

    /// <summary>A fatal queue callback error is not misreported as a readable directory's access error.</summary>
    [Fact]
    public async Task QueueDispatchFailure_IsNotSwallowedByDirectoryEnumeration()
    {
        string root = Path.Combine(Path.GetTempPath(), "AegisDispatch_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "readme.txt"), "Inert dispatch fixture.");
            var coverage = new ScanCoverageSummary(); var walker = new DirectoryWalker();
            using var scope = walker.BeginCoverage(coverage);
            var error = await Assert.ThrowsAnyAsync<Exception>(() => walker.EnumerateDirectorySafelyAsync(root, true,
                _ => throw new IOException("Synthetic queue fault"), default));
            Assert.IsType<IOException>(error.InnerException);
            Assert.Equal(0, coverage.UnreadableDirectories);
        }
        finally { Directory.Delete(root, true); }
    }

    /// <summary>A callback's cancelled work must propagate even when the outer scan token has not been cancelled.</summary>
    [Fact]
    public async Task QueueDispatchCancellation_Propagates()
    {
        string root = Path.Combine(Path.GetTempPath(), "AegisDispatchCancel_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "readme.txt"), "Inert dispatch fixture.");
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new DirectoryWalker().EnumerateDirectorySafelyAsync(root, true,
                _ => throw new OperationCanceledException("Synthetic queue cancellation"), default));
        }
        finally { Directory.Delete(root, true); }
    }

    /// <summary>Old reports without a coverage field remain unknown instead of inheriting today's complete default.</summary>
    [Fact]
    public async Task LegacyReport_ExplicitlyRecordsUnknownCoverage()
    {
        string root = Path.Combine(Path.GetTempPath(), "AegisReportCoverage_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var node = JsonNode.Parse(JsonSerializer.Serialize(new[] { new ScanReportRecord { Result = new() { Status = ScanStatus.Completed } } }))!;
            node[0]!["Result"]!.AsObject().Remove("Coverage");
            string path = Path.Combine(root, "history.json");
            await File.WriteAllTextAsync(path, node.ToJsonString());
            var result = Assert.Single(await new ScanReportHistoryStore(path).LoadAsync());
            Assert.False(result.Result.Coverage.IsComplete);
            Assert.Contains("LegacyReportCoverageNotRecorded", result.Result.Coverage.Limitations);
        }
        finally { Directory.Delete(root, true); }
    }

    /// <summary>An observer's exception cannot rewrite an acknowledged committed action into UI failure.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CommittedOperation_ObserverFailureDoesNotChangeSuccess(bool restore)
    {
        var client = new ServiceQuarantineClient(new SuccessfulIpc()); int observed = 0;
        if (restore)
        {
            client.OnFileRestored += _ => throw new InvalidOperationException("Synthetic observer error");
            client.OnFileRestored += _ => observed++;
            Assert.True(await client.RestoreFileAsync(12));
        }
        else
        {
            client.OnFileDeleted += _ => throw new InvalidOperationException("Synthetic observer error");
            client.OnFileDeleted += _ => observed++;
            Assert.True(await client.DeleteQuarantinedAsync(12));
        }
        Assert.Equal(1, observed); Assert.Null(client.LastError);
    }

    private sealed class FakeHub(DetectionResult result) : IDetectionHub
    {
        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => [];
        public void RegisterDetector(IDetectorPlugin detector) { }
        public bool UnregisterDetector(string detectorId) => false;
        public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default) => Task.FromResult(result);
    }

    private sealed class FakeVolumes(string root) : IScanVolumeTargetResolver
    {
        public Task<ScanVolumeTargetResolution> ResolveAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new ScanVolumeTargetResolution { VolumeRoots = [root, root], Limitations = ["LocalVolumeNotReadyOrAccessible"] });
    }

    private sealed class SuccessfulIpc : IServiceIpcClient, IServiceRequestClient
    {
        public bool IsConnected => true;
        public Task ConnectAsync() => Task.CompletedTask;
        public Task SendCommandAsync(ServiceCommand command) => Task.CompletedTask;
        public Task<ProtectionStatus> GetStatusAsync() => Task.FromResult(new ProtectionStatus { ProtectionLevel = "Unknown" });
        public Task<ServiceReply> RequestAsync(ServiceCommandType command, string? payload = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new ServiceReply { Success = true });
        public event Action<ThreatNotification>? ThreatDetected { add { } remove { } }
        public event Action<ProtectionStatus>? StatusChanged { add { } remove { } }
        public void Dispose() { }
    }
}
