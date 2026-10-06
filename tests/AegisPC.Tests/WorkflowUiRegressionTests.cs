using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Collections.Generic;
using System.Threading;
using AegisPC.Contracts.Services;
using System.Threading.Tasks;
using AegisPC.App.Services;
using AegisPC.App.ViewModels;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Xunit;

namespace AegisPC.Tests;

public class WorkflowUiRegressionTests
{
    [Theory]
    [InlineData(85)]
    [InlineData(100)]
    public void HighRiskWithoutAction_DoesNotClaimQuarantine(int score)
    {
        var finding = new SecurityFinding { RiskScore = score, Status = FindingStatus.Active };
        Assert.DoesNotContain("Karantinaya", ScanReportGenerator.DetermineActionTaken(finding));
    }

    [Fact]
    public void ResolvedWithoutAction_DoesNotInventQuarantine()
    {
        Assert.DoesNotContain("Karantinaya", ScanReportGenerator.DetermineActionTaken(new SecurityFinding { Status = FindingStatus.Resolved }));
    }

    [Fact]
    public void IncompleteReport_DoesNotClaimSystemSafe()
    {
        var report = ScanReportGenerator.GenerateTextReport(DateTime.UtcNow, "1 sn", "Custom", 1, null, failedCount: 2);
        Assert.DoesNotContain("Sistem Güvende", report);
        Assert.DoesNotContain("koruması güncel ve güvenlidir", report);
        Assert.Contains("eksik", report, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FreshScan_ClearsPreviousFailureAndResourceCounters()
    {
        var vm = new ScanViewModel { FailedCount = 4, TimedOutCount = 2, SkippedCount = 3, CpuUsagePercent = 20, RamUsageMb = 100 };
        vm.ResetScanState();
        Assert.Equal(0, vm.FailedCount);
        Assert.Equal(0, vm.TimedOutCount);
        Assert.Equal(0, vm.SkippedCount);
        Assert.Equal(0, vm.CpuUsagePercent);
        vm.CloseResults();
    }

    [Fact]
    public void PercentageAlone_CannotProveMemoryOrRegistryStageComplete()
    {
        var vm = new ScanViewModel { IsScanning = true, ProgressPercentage = 60 };
        Assert.False(vm.IsStep1Done);
        Assert.False(vm.IsStep2Done);
        Assert.False(vm.IsStep3Done);
        Assert.False(vm.IsStep4Done);
        vm.CloseResults();
    }

    [Fact]
    public void ChangingResourceMetric_RaisesFormattedBindingNotification()
    {
        var vm = new ScanViewModel();
        bool notified = false;
        vm.PropertyChanged += (_, e) => notified |= e.PropertyName == nameof(ScanViewModel.CpuAndRamFormatted);
        vm.CpuUsagePercent = 1.25;
        Assert.True(notified);
    }

    [Fact]
    public void UnavailableCpu_IsNotDisplayedAsMeasuredZero()
    {
        var vm = new ScanViewModel();
        Assert.Contains("CPU: ölçülüyor", vm.CpuAndRamFormatted);
        vm.IsCpuTelemetryAvailable = true;
        Assert.Contains("CPU: %", vm.CpuAndRamFormatted);
        Assert.DoesNotContain("CPU: ölçülüyor", vm.CpuAndRamFormatted);
    }

    [Fact]
    public void ReportHistory_HasSeparatePersistedStore()
    {
        Assert.NotNull(typeof(ScanReportGenerator).Assembly.GetType("AegisPC.App.Services.ScanReportHistoryStore"));
    }

    [Fact]
    public async Task ExcludeWithoutPersistenceService_DoesNotRemoveFinding()
    {
        var vm = new ScanViewModel();
        var finding = new SecurityFinding { ObjectPath = "unavailable-provider.bin" };
        var item = new SelectableThreatModel { Location = finding.ObjectPath, Finding = finding };
        vm.ThreatResults.Add(item);
        vm.ScanFindings.Add(finding);
        await vm.ExcludeFindingAsync(item);
        Assert.Contains(item, vm.ThreatResults);
        Assert.False(finding.IsAllowlisted);
    }

    [Fact]
    public async Task History_RoundTripsCancelledResult_AndDetachesMutableFindings()
    {
        string directory = NewFixtureDirectory();
        try
        {
            var store = new ScanReportHistoryStore(Path.Combine(directory, "history.json"));
            var result = new ScanResult
            {
                StartedAt = DateTime.UtcNow, Status = ScanStatus.Cancelled, ScannedFiles = 3, TotalFiles = 12, FailedFiles = 2,
                Findings = new() { new SecurityFinding { Title = "Benign regression finding", RiskScore = 95, Status = FindingStatus.Active } }
            };
            var record = new ScanReportRecord { Result = result };
            await store.AppendAsync(record);
            result.Findings.Clear();
            var loaded = Assert.Single(await store.LoadAsync());
            Assert.Equal(ScanStatus.Cancelled, loaded.Result.Status);
            Assert.Equal(2, loaded.Result.FailedFiles);
            Assert.Single(loaded.Result.Findings);
            using var json = JsonDocument.Parse(ScanReportGenerator.GenerateJsonReport(loaded));
            Assert.Equal("Cancelled", json.RootElement.GetProperty("Status").GetString());
            Assert.False(json.RootElement.GetProperty("ReportedCoverageComplete").GetBoolean());
            Assert.DoesNotContain("Karantinaya", json.RootElement.GetProperty("Findings")[0].GetProperty("ActionTaken").GetString()!);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task History_RejectsRunningResults_AndMalformedHistory()
    {
        string directory = NewFixtureDirectory();
        try
        {
            string path = Path.Combine(directory, "history.json");
            var store = new ScanReportHistoryStore(path);
            await Assert.ThrowsAsync<ArgumentException>(() => store.AppendAsync(new ScanReportRecord { Result = new ScanResult { Status = ScanStatus.Running } }));
            Assert.False(File.Exists(path));
            await File.WriteAllTextAsync(path, "not a JSON history");
            await Assert.ThrowsAsync<JsonException>(() => store.LoadAsync());
            await Assert.ThrowsAsync<JsonException>(() => store.AppendAsync(new ScanReportRecord { Result = new ScanResult { Status = ScanStatus.Completed } }));
            Assert.Equal("not a JSON history", await File.ReadAllTextAsync(path));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task History_UpdatingConfirmedAction_DoesNotDuplicateReport()
    {
        string directory = NewFixtureDirectory();
        try
        {
            var store = new ScanReportHistoryStore(Path.Combine(directory, "history.json"));
            var record = new ScanReportRecord { Result = new ScanResult { Status = ScanStatus.Completed } };
            await store.AppendAsync(record);
            record.Actions["fixture-path.bin"] = "Karantinaya alındı";
            await store.AppendAsync(record);
            var loaded = Assert.Single(await store.LoadAsync());
            Assert.Equal("Karantinaya alındı", loaded.Actions["fixture-path.bin"]);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task FailedCompletion_IsNotDisplayedAsCompletedOrClean()
    {
        string directory = NewFixtureDirectory();
        try
        {
            var store = new ScanReportHistoryStore(Path.Combine(directory, "history.json"));
            var vm = new ScanViewModel(reportHistoryStore: store);
            vm.ResetScanState();
            vm.ProgressPercentage = 45;
            typeof(ScanViewModel).GetMethod("OnScanCompleted", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(vm,
                new object[] { new ScanResult { Status = ScanStatus.Failed, StartedAt = DateTime.UtcNow, ScannedFiles = 4, FailedFiles = 1 } });
            Assert.Contains("Başarısız", vm.ScanResultTitle);
            Assert.True(vm.ProgressPercentage < 100);
            Assert.Equal(1, vm.FailedCount);
            Assert.DoesNotContain("temiz", vm.CleanStateTitle);
            Assert.Equal(ScanStatus.Failed, Assert.Single(await store.LoadAsync()).Result.Status);
            await vm.RefreshReportsAsync();
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExcludeWithContentHash_UsesHashNotPath_AndDoesNotLieOnFailure(bool failPersistence)
    {
        var exclusions = new FakeExclusions { Fail = failPersistence };
        var vm = new ScanViewModel(exclusionService: exclusions);
        var finding = new SecurityFinding { ObjectPath = "benign-fixture.bin", SHA256 = new string('A', 64) };
        var item = new SelectableThreatModel { Location = finding.ObjectPath, Finding = finding };
        vm.ThreatResults.Add(item);
        vm.ScanFindings.Add(finding);
        await vm.ExcludeFindingAsync(item);
        Assert.Equal(1, exclusions.HashAdds);
        Assert.Equal(0, exclusions.PathAdds);
        Assert.Equal(failPersistence, vm.ThreatResults.Contains(item));
        Assert.Equal(!failPersistence, finding.IsAllowlisted);
    }

    [Fact]
    public async Task ExcludeWithoutHash_AndWithoutInteractiveConfirmation_DoesNotAddPathRule()
    {
        var exclusions = new FakeExclusions();
        var vm = new ScanViewModel(exclusionService: exclusions);
        var finding = new SecurityFinding { ObjectPath = "benign-fixture.bin" };
        var item = new SelectableThreatModel { Location = finding.ObjectPath, Finding = finding };
        vm.ThreatResults.Add(item);
        await vm.ExcludeFindingAsync(item);
        Assert.Equal(0, exclusions.PathAdds);
        Assert.Contains(item, vm.ThreatResults);
    }

    [Fact]
    public void LateCancellationRequest_DoesNotOverrideActualCompletedResult()
    {
        var vm = new ScanViewModel();
        typeof(ScanViewModel).GetField("_isCancellationRequested", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(vm, true);
        typeof(ScanViewModel).GetMethod("OnScanCompleted", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(vm,
            new object[] { new ScanResult { Status = ScanStatus.Completed, StartedAt = DateTime.UtcNow } });
        Assert.False(vm.IsCancellationRequested);
        Assert.DoesNotContain("İptal", vm.ScanResultTitle);
        Assert.Equal(100, vm.ProgressPercentage);
    }

    private sealed class FakeExclusions : IExclusionService
    {
        public bool Fail { get; init; }
        public int HashAdds { get; private set; }
        public int PathAdds { get; private set; }
        public bool IsExcluded(string? filePath, string? sha256 = null) => false;
        public Task<bool> IsExcludedAsync(string? filePath, string? sha256 = null, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<IReadOnlyList<ExclusionEntry>> GetAllExclusionsAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<ExclusionEntry>>(Array.Empty<ExclusionEntry>());
        public Task<ExclusionEntry> AddPathExclusionAsync(string path, bool includeSubdirectories = true, string? reason = null, CancellationToken cancellationToken = default)
        {
            PathAdds++;
            return Task.FromResult(new ExclusionEntry { Value = path });
        }
        public Task<ExclusionEntry> AddSha256ExclusionAsync(string sha256, string? reason = null, CancellationToken cancellationToken = default)
        {
            HashAdds++;
            if (Fail) throw new IOException("Benign persistence failure fixture");
            return Task.FromResult(new ExclusionEntry { Type = ExclusionType.Sha256, Value = sha256 });
        }
        public void AddTemporaryPathExclusion(string path, TimeSpan duration, string? reason = null) { }
        public Task<bool> RemoveExclusionAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public bool IsRootOrSystemDirectory(string path) => false;
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private static string NewFixtureDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(), "UltronWorkflowUi_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}
