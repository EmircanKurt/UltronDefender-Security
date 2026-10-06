using System.Reflection;
using System.IO;
using System.Text.Json;
using AegisPC.App.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using AegisPC.Service.IPC;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert coverage, ownership and UI service-facade regression checks; not a malware corpus.</summary>
public sealed class ProtectionCoverageTruthTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisCoverage_" + Guid.NewGuid().ToString("N"));
    /// <summary>Creates only an isolated harmless fixture directory.</summary>
    public ProtectionCoverageTruthTests() => Directory.CreateDirectory(_root);

    /// <summary>Freshness rejects missing, future, incompatible and stale observations.</summary>
    [Theory]
    [InlineData(0, 1, true)]
    [InlineData(15, 1, true)]
    [InlineData(16, 1, false)]
    [InlineData(-1, 1, false)]
    [InlineData(0, 2, false)]
    public void HealthFreshness_IsNotDesiredSettings(int ageSeconds, int version, bool fresh)
    {
        var now = DateTime.UtcNow;
        Assert.Equal(fresh, new ProtectionHealthSnapshot { ProtocolVersion = version, CapturedAtUtc = now.AddSeconds(-ageSeconds) }.IsFresh(now));
        Assert.False(new ProtectionHealthSnapshot().IsFresh(now));
    }

    /// <summary>Unavailable telemetry cannot make desired protection healthy.</summary>
    [Theory]
    [InlineData(false, false, 0, ProtectionHealthState.Degraded)]
    [InlineData(true, true, -1, ProtectionHealthState.Degraded)]
    [InlineData(true, true, 2, ProtectionHealthState.Degraded)]
    [InlineData(true, true, 0, ProtectionHealthState.Healthy)]
    public void Sampler_RequiresObservedSubscriptions(bool process, bool image, long lost, ProtectionHealthState expected)
    {
        var type = typeof(NamedPipeServer).Assembly.GetType("AegisPC.Service.IPC.ProtectionHealthSampler")!;
        var method = type.GetMethod("Capture", BindingFlags.Static | BindingFlags.NonPublic)!;
        var snapshot = (ProtectionHealthSnapshot)method.Invoke(null,
            new object?[] { true, true, new RealTimeCoverageSnapshot(2, false, false, 0, 0), process, image, lost, true, false, true })!;
        Assert.Equal(expected, snapshot.State);
        Assert.False(snapshot.NetworkFlowInspectionActive);
        Assert.False(snapshot.KernelBridgeConnected);
    }

    /// <summary>Coverage counters survive report serialization instead of silently resetting to complete.</summary>
    [Fact]
    public void Coverage_RoundTripRetainsInspectionGaps()
    {
        var coverage = new ScanCoverageSummary();
        coverage.RecordDirectoryError(); coverage.RecordProcessError(); coverage.RecordPartialArchive();
        coverage.RecordReparseSkip(); coverage.RecordLimitation("UnreadableStartupRegistry");
        var restored = JsonSerializer.Deserialize<ScanCoverageSummary>(JsonSerializer.Serialize(coverage))!;
        Assert.False(restored.IsComplete);
        Assert.Equal(1, restored.UnreadableDirectories); Assert.Equal(1, restored.UnreadableProcesses);
        Assert.Equal(1, restored.PartialArchives); Assert.Equal(1, restored.SkippedReparsePoints);
        Assert.Contains("UnreadableStartupRegistry", restored.Limitations);
    }

    /// <summary>A successfully finished job with an unreadable source remains partial in both export formats.</summary>
    [Fact]
    public void CompletedReport_DoesNotHideDirectoryCoverageGap()
    {
        var result = new ScanResult { Status = ScanStatus.Completed };
        result.Coverage.RecordDirectoryError();
        var record = new ScanReportRecord { Result = result };
        using var json = JsonDocument.Parse(ScanReportGenerator.GenerateJsonReport(record));
        Assert.False(json.RootElement.GetProperty("ReportedCoverageComplete").GetBoolean());
        string text = ScanReportGenerator.GenerateTextReport(DateTime.Now, "1s", "Custom", 0, [], coverage: result.Coverage);
        Assert.Contains("Kısmi", text);
    }

    /// <summary>Custom single-file scans enqueue the exact file once and never scan its sibling.</summary>
    [Fact]
    public async Task SingleFileCustomScan_QueuesOnlyRequestedFile()
    {
        string file = Path.Combine(_root, "benign.txt");
        await File.WriteAllTextAsync(file, "Benign custom scan fixture.");
        await File.WriteAllTextAsync(Path.Combine(_root, "sibling.txt"), "Not in scope.");
        var queued = new List<string>();
        await new DirectoryWalker().WalkDirectoriesForScanTypeAsync(ScanType.Custom, file,
            path => { queued.Add(path); return Task.CompletedTask; }, _ => { }, CancellationToken.None);
        Assert.Equal(file, Assert.Single(queued));
    }

    /// <summary>Cancellation does not enqueue a new single-file job.</summary>
    [Fact]
    public async Task SingleFileCustomScan_CancelledBeforeQueueing()
    {
        string file = Path.Combine(_root, "benign.txt"); await File.WriteAllTextAsync(file, "Benign fixture.");
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => new DirectoryWalker().WalkDirectoriesForScanTypeAsync(
            ScanType.Custom, file, _ => throw new Xunit.Sdk.XunitException("Cancelled file was queued."), _ => { }, cancelled.Token));
    }

    /// <summary>Two concurrent walker contexts cannot contaminate each other's coverage.</summary>
    [Fact]
    public async Task DirectoryCoverageScope_IsSessionLocal()
    {
        var walker = new DirectoryWalker();
        var missing = new ScanCoverageSummary(); var empty = new ScanCoverageSummary();
        async Task Walk(string path, ScanCoverageSummary summary)
        {
            using var scope = walker.BeginCoverage(summary);
            await walker.EnumerateDirectorySafelyAsync(path, true, _ => Task.CompletedTask, CancellationToken.None);
        }
        await Task.WhenAll(Task.Run(() => Walk(Path.Combine(_root, "missing"), missing)), Task.Run(() => Walk(_root, empty)));
        Assert.Equal(1, missing.UnreadableDirectories); Assert.True(empty.IsComplete);
    }

    /// <summary>Unknown old owner and another user's record are denied to standard callers.</summary>
    [Theory]
    [InlineData(null, "S-1-5-21-1001", false, false)]
    [InlineData("S-1-5-21-1002", "S-1-5-21-1001", false, false)]
    [InlineData("S-1-5-21-1001", "S-1-5-21-1001", false, true)]
    [InlineData(null, "S-1-5-21-1001", true, true)]
    public void RecordIsolation_DoesNotInferLegacyOwnership(string? owner, string sid, bool admin, bool allowed) =>
        Assert.Equal(allowed, QuarantineAccessPolicy.CanAccess(new QuarantineEntry { OwnerSid = owner }, sid, admin));

    /// <summary>The UI cannot pretend a disconnected service action completed.</summary>
    [Fact]
    public async Task UiQuarantineFacade_DisconnectedNeverWritesOrReportsSuccess()
    {
        var client = new ServiceQuarantineClient(new FakeIpc(false));
        bool restored = await client.RestoreFileAsync(1);
        Assert.False(restored); Assert.NotNull(client.LastError);
        await Assert.ThrowsAsync<IOException>(() => client.GetQuarantinedItemsAsync());
    }

    /// <summary>Unacknowledged operations do not generate UI action events.</summary>
    [Fact]
    public async Task UiQuarantineFacade_FailedReplyIsNotAction()
    {
        var client = new ServiceQuarantineClient(new FakeIpc(true)); int events = 0;
        client.OnFileDeleted += _ => events++;
        Assert.False(await client.DeleteQuarantinedAsync(4)); Assert.Equal(0, events);
    }

    /// <summary>Removes only the fixture root.</summary>
    public void Dispose() => Directory.Delete(_root, recursive: true);

    private sealed class FakeIpc(bool connected) : IServiceIpcClient, IServiceRequestClient
    {
        public bool IsConnected => connected;
        public Task ConnectAsync() => Task.CompletedTask;
        public Task SendCommandAsync(ServiceCommand command) => Task.CompletedTask;
        public Task<ProtectionStatus> GetStatusAsync() => Task.FromResult(new ProtectionStatus { ProtectionLevel = "Unknown" });
        public Task<ServiceReply> RequestAsync(ServiceCommandType command, string? payload = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ServiceReply { Success = false, Code = "ActionNotCompleted" });
        public event Action<ThreatNotification>? ThreatDetected { add { } remove { } }
        public event Action<ProtectionStatus>? StatusChanged { add { } remove { } }
        public void Dispose() { }
    }
}
