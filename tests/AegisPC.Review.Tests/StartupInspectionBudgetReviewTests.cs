using System;
using System.IO;
using System.Reflection;
using AegisPC.App.ViewModels;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Startup inspection timing fixtures share inert test collaborators without enlarging the existing safety fixture.</summary>
public sealed partial class StartupSweepSafetyTests
{
    /// <summary>Specific inspection gaps survive the sweep's aggregate report instead of being collapsed into a generic counter.</summary>
    [Fact]
    public async Task InspectionReasonCodes_SurviveFinalReport()
    {
        string file = CreateBenignFile();
        var coordinator = new RecordingCoordinator();
        var vault = new RecordingVault();
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult
        {
            Verdict = RealTimeVerdict.Unknown, InspectionComplete = false,
            CoverageLimitations = ["InertFixtureInspectionGap"]
        });
        var result = await new StartupSecuritySweepService(engine, vault, scanCoordinator: coordinator).RunSweepAsync([file]);
        Assert.Equal(1, result.IncompleteCount);
        Assert.Contains("InertFixtureInspectionGap", coordinator.LastResult!.Coverage.Limitations);
        Assert.Equal(0, vault.BoundCalls + vault.UnboundCalls);
    }

    /// <summary>Incomplete module coverage is visible even with zero file-error counters and never reported as a failed job or complete clean scan.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public void CompletedPartialCoverage_ProducesHonestWarning(int findingCount)
    {
        var toast = new FakeToastService();
        var viewModel = new ScanViewModel(toastService: toast);
        var result = new ScanResult { Status = ScanStatus.Completed, ScannedFiles = 1 };
        result.Coverage.RecordLimitation("BenignModuleByteBudget");
        typeof(ScanViewModel).GetMethod("NotifyFinalScanStatus", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(viewModel, [result, findingCount]);
        var notification = Assert.Single(toast.SentToasts);
        Assert.Equal("Warning", notification.Type);
        Assert.Contains("eksik", notification.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("başarısız", notification.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A noncooperative worker remains owned until it exits; budget expiry is visible and never silently becomes clean.</summary>
    [Fact]
    public async Task NoncooperativeWorker_IsNotAbandonedOrReportedClean()
    {
        string file = CreateBenignFile();
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var heartbeat = new TaskCompletionSource<ScanProgress>(TaskCreationOptions.RunContinuationsAsynchronously);
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult())
        {
            AsyncInspect = async (_, _) =>
            {
                await release.Task;
                return new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean, SHA256 = ValidHash(file) };
            }
        };
        var coordinator = new ScanCoordinatorService(new FinalReviewScanRegressionTests.ControlledScanner(), new SecurityFindingService());
        coordinator.ProgressChanged += p =>
        {
            if (p.Phase.Contains("durması bekleniyor")) heartbeat.TrySetResult(p);
        };
        var sweep = new StartupSecuritySweepService(engine, new RecordingVault(), scanCoordinator: coordinator,
            inspectionTimeout: TimeSpan.FromMilliseconds(50));
        var task = sweep.RunSweepAsync(new[] { file });
        try
        {
            var progress = await heartbeat.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(task.IsCompleted);
            Assert.True(coordinator.IsScanning);
            Assert.Equal(0, progress.ScannedFiles);
        }
        finally { release.TrySetResult(true); }
        var result = await task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, result.TimedOutCount);
        Assert.Equal(0, result.CleanCount);
        Assert.False(coordinator.IsScanning);
    }

    /// <summary>A timed-out inspection preserves the benign file and continues to the next candidate, with real terminal counters.</summary>
    [Fact]
    public async Task InspectionBudgetExpiry_IsIncompleteAndNextFileStillRuns()
    {
        string first = CreateBenignFile();
        string second = Path.Combine(_dir, "second.txt");
        File.WriteAllText(second, "benign second candidate");
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean })
        {
            AsyncInspect = async (path, token) =>
            {
                if (path == first) await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean,
                    InspectionComplete = true, RecommendedPolicy = RealTimePolicyAction.Allow, SHA256 = ValidHash(path) };
            }
        };
        var vault = new RecordingVault();
        var coordinator = new RecordingCoordinator();
        var sweep = new StartupSecuritySweepService(engine, vault, scanCoordinator: coordinator,
            inspectionTimeout: TimeSpan.FromMilliseconds(50));
        var result = await sweep.RunSweepAsync(new[] { first, second }).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(StartupSweepStatus.Completed, result.FinalStatus);
        Assert.Equal(2, engine.Inspections);
        Assert.Equal(2, result.TotalScanned);
        Assert.Equal(1, result.TimedOutCount);
        Assert.Equal(1, result.IncompleteCount);
        Assert.Equal(1, result.CleanCount);
        Assert.Equal(1, coordinator.LastResult!.TimedOutFiles);
        Assert.Equal(0, coordinator.LastResult.FailedFiles);
        Assert.False(coordinator.LastResult.Coverage.IsComplete);
        Assert.Contains("StartupInspectionTimedOut", coordinator.LastResult.Coverage.Limitations);
        Assert.Equal(0, vault.BoundCalls + vault.UnboundCalls);
        Assert.True(File.Exists(first) && File.Exists(second));
    }

    /// <summary>Progress while the engine is waiting names the actual file without claiming it is already inspected.</summary>
    [Fact]
    public async Task WaitingInspection_ReportsTelemetryAndDoesNotPrematurelyCountFile()
    {
        string file = CreateBenignFile();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var heartbeat = new TaskCompletionSource<ScanProgress>(TaskCreationOptions.RunContinuationsAsynchronously);
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult())
        {
            AsyncInspect = async (_, token) =>
            {
                entered.TrySetResult(true);
                await release.Task.WaitAsync(token);
                return new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean, SHA256 = ValidHash(file) };
            }
        };
        var coordinator = new ScanCoordinatorService(new FinalReviewScanRegressionTests.ControlledScanner(), new SecurityFindingService());
        coordinator.ProgressChanged += p =>
        {
            if (p.IsCpuTelemetryAvailable && p.CurrentFile == file) heartbeat.TrySetResult(p);
        };
        var sweep = new StartupSecuritySweepService(engine, new RecordingVault(), scanCoordinator: coordinator);
        var task = sweep.RunSweepAsync(new[] { file });
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var progress = await heartbeat.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(0, progress.ScannedFiles);
            Assert.Equal(0, progress.NewlyScanned);
            Assert.True(progress.RamUsageMb > 0);
            Assert.True(progress.ElapsedTime >= TimeSpan.FromMilliseconds(250));
            Assert.Equal("Başlangıç dosya taraması", progress.Phase);
            Assert.Equal(1, progress.ActiveWorkers);
        }
        finally { release.TrySetResult(true); }
        Assert.Equal(1, (await task.WaitAsync(TimeSpan.FromSeconds(5))).TotalScanned);
    }

    /// <summary>Actual user cancellation is not recorded as a per-file timeout or a clean result.</summary>
    [Fact]
    public async Task UserCancellation_RemainsCancellationAndDoesNotCountPendingFile()
    {
        string file = CreateBenignFile();
        using var cancellation = new CancellationTokenSource();
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult())
        {
            AsyncInspect = async (_, token) =>
            {
                cancellation.Cancel();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return new RealTimeVerdictResult();
            }
        };
        var result = await new StartupSecuritySweepService(engine, new RecordingVault())
            .RunSweepAsync(new[] { file }, cancellation.Token).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(StartupSweepStatus.Cancelled, result.FinalStatus);
        Assert.Equal(0, result.TotalScanned);
        Assert.Equal(0, result.TimedOutCount);
        Assert.Equal(0, result.CleanCount);
    }

    /// <summary>An unrelated cancelled worker is a scanner failure, never an invented user cancellation.</summary>
    [Fact]
    public async Task ForeignCancellation_IsFailureRatherThanUserCancellation()
    {
        string file = CreateBenignFile();
        var engine = new RecordingEngine(_ => throw new OperationCanceledException(new CancellationToken(true)));
        var result = await new StartupSecuritySweepService(engine, new RecordingVault())
            .RunSweepAsync(new[] { file }).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(StartupSweepStatus.Failed, result.FinalStatus);
        Assert.Equal(0, result.CleanCount);
        Assert.Equal(0, result.TimedOutCount);
    }

}
