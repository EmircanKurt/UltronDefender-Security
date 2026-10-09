using System.Diagnostics;
using System.IO;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Measurement-contract fixtures only: no scanner engines, action adapters, watchers, service, rules or network.</summary>
public sealed class ReviewStageOneMeasurementTests
{
    private static string InertPath(string name = "fixture.txt") => Path.Combine(Path.GetTempPath(), "UltronMeasurementFixture-" + Guid.NewGuid().ToString("N"), name);

    [Fact]
    public void LegacySuccess_DoesNotInventCoverageOrStages()
    {
        using var recorder = new ScanMeasurementRecorder();
        using (var attempt = recorder.Begin(InertPath(), Stopwatch.GetTimestamp()))
        {
            var result = FileScanDetailedResult.CreateSuccess("fixture", null, TimeSpan.Zero);
            Assert.Null(result.InspectionComplete);
            attempt.Complete(result);
        }
        var summary = recorder.Snapshot();
        var volume = Assert.Single(summary.Volumes);
        Assert.Equal(1, volume.SuccessfulAttempts);
        Assert.Equal(0, volume.CompleteCoverageAttempts);
        Assert.Equal(1, volume.UnknownCoverageAttempts);
        Assert.False(volume.LogicalInputSizesComplete);
        Assert.Equal(1, volume.UnknownLogicalInputSizeAttempts);
        Assert.Null(summary.DiscoveryStageMs);
        Assert.Null(summary.StabilityStageMs);
        Assert.Null(summary.HashStageMs);
        Assert.Null(summary.ContentStageMs);
        Assert.Null(summary.DetectorStageMs);
        Assert.Null(summary.PhysicalInputMiBPerSecond);
        Assert.Null(volume.OutputQueueP95UpperBoundMs);
        Assert.Empty(summary.Stages);
        Assert.Equal(Environment.ProcessorCount, summary.CpuNormalizationProcessorCount);
        if (summary.ProcessCpuPercent is { } cpu) Assert.InRange(cpu, 0, 100);
    }

    [Fact]
    public void OutcomesAndCoverage_AreIndependentAndIdempotent()
    {
        using var recorder = new ScanMeasurementRecorder();
        string path = InertPath();
        void End(FileScanOutcome outcome, bool? complete, bool cached = false)
        {
            var attempt = recorder.Begin(path, Stopwatch.GetTimestamp());
            attempt.Complete(outcome, complete, cached);
            attempt.Complete(FileScanOutcome.Timeout, false);
            attempt.Dispose(); attempt.Dispose();
        }
        End(FileScanOutcome.Success, true, cached: true);
        End(FileScanOutcome.Success, null);
        End(FileScanOutcome.Failed, false);
        End(FileScanOutcome.Failed, null);
        End(FileScanOutcome.Timeout, false);
        End(FileScanOutcome.Skipped, null);
        var interrupted = recorder.Begin(path, Stopwatch.GetTimestamp());
        interrupted.Dispose(); interrupted.Dispose();

        var volume = Assert.Single(recorder.Snapshot().Volumes);
        Assert.Equal(7, volume.Attempts);
        Assert.Equal(7, volume.FinishedAttempts);
        Assert.Equal(2, volume.SuccessfulAttempts);
        Assert.Equal(2, volume.FailedAttempts);
        Assert.Equal(1, volume.TimedOutAttempts);
        Assert.Equal(1, volume.SkippedAttempts);
        Assert.Equal(1, volume.InterruptedAttempts);
        Assert.Equal(1, volume.CompleteCoverageAttempts);
        Assert.Equal(2, volume.PartialCoverageAttempts);
        Assert.Equal(4, volume.UnknownCoverageAttempts);
        Assert.Equal(1, volume.CachedAttempts);
        Assert.Equal(volume.FinishedAttempts, volume.SuccessfulAttempts + volume.FailedAttempts + volume.TimedOutAttempts + volume.SkippedAttempts + volume.InterruptedAttempts);
        Assert.Equal(volume.FinishedAttempts, volume.CompleteCoverageAttempts + volume.PartialCoverageAttempts + volume.UnknownCoverageAttempts);
    }

    [Fact]
    public async Task AnalysisEndsBeforeResultQueueWaiting()
    {
        using var recorder = new ScanMeasurementRecorder();
        using var attempt = recorder.Begin(InertPath(), Stopwatch.GetTimestamp());
        attempt.Complete(FileScanOutcome.Success, true);
        var before = Assert.Single(recorder.Snapshot().Volumes);
        var wait = attempt.MeasureOutputQueueWait();
        await Task.Delay(20);
        wait.Dispose(); wait.Dispose();
        var after = Assert.Single(recorder.Snapshot().Volumes);
        Assert.Equal(before.AnalysisP95UpperBoundMs, after.AnalysisP95UpperBoundMs);
        Assert.Equal(1, after.FinishedAttempts);
        Assert.Equal(1, after.OutputQueueWaitSamples);
        Assert.True(after.OutputQueueP95UpperBoundMs >= 16);
    }

    [Fact]
    public void StageScopesWithoutAnOwnedSink_AreIgnored()
    {
        using var recorder = new ScanMeasurementRecorder();
        using (ScanStageMeasurements.Measure(ScanStageTiming.Hash)) { }
        Assert.Null(recorder.Snapshot().HashStageMs);
        using (recorder.BeginPipelineStages())
        using (ScanStageMeasurements.Measure(ScanStageTiming.Discovery)) { }
        var summary = recorder.Snapshot();
        Assert.NotNull(summary.DiscoveryStageMs);
        Assert.Null(summary.HashStageMs);
        Assert.Equal("Discovery", Assert.Single(summary.Stages).Stage);
    }

    [Fact]
    public void NestedSameStage_IsCountedOnceAndDifferentStageRemainsObserved()
    {
        using var recorder = new ScanMeasurementRecorder();
        using (recorder.BeginPipelineStages())
        using (ScanStageMeasurements.Measure(ScanStageTiming.Detector))
        {
            using (ScanStageMeasurements.Measure(ScanStageTiming.Detector)) { }
            var hash = ScanStageMeasurements.Measure(ScanStageTiming.Hash);
            hash.Dispose(); hash.Dispose();
        }
        var stages = recorder.Snapshot().Stages;
        Assert.Equal(2, stages.Count);
        Assert.All(stages, stage => Assert.Equal(1, stage.Samples));
        Assert.All(stages, stage => Assert.True(stage.TotalMs >= 0));
    }

    [Fact]
    public async Task ParallelAsyncAttempts_RetainSeparateStageScopes()
    {
        using var recorder = new ScanMeasurementRecorder();
        string path = InertPath();
        using (recorder.BeginPipelineStages())
        {
            await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
            {
                using var attempt = recorder.Begin(path, Stopwatch.GetTimestamp());
                using (ScanStageMeasurements.Measure(ScanStageTiming.Hash)) await Task.Delay(5);
                using (ScanStageMeasurements.Measure(ScanStageTiming.Content)) await Task.Yield();
                attempt.Complete(FileScanOutcome.Success, true);
            })));
        }
        var summary = recorder.Snapshot();
        Assert.Equal(8, Assert.Single(summary.Volumes).CompleteCoverageAttempts);
        Assert.Equal(2, summary.Stages.Count);
        Assert.All(summary.Stages, stage => Assert.Equal(8, stage.Samples));
    }

    [Fact]
    public void OutOfOrderScopeDisposal_DoesNotLeakAClosedSink()
    {
        using var recorder = new ScanMeasurementRecorder();
        var first = recorder.BeginPipelineStages();
        var second = recorder.BeginPipelineStages();
        first.Dispose(); second.Dispose();
        using (ScanStageMeasurements.Measure(ScanStageTiming.Hash)) { }
        Assert.Null(recorder.Snapshot().HashStageMs);
    }

    [Fact]
    public void OutOfOrderStageDisposal_DoesNotSuppressTheNextOperation()
    {
        using var recorder = new ScanMeasurementRecorder();
        using (recorder.BeginPipelineStages())
        {
            var first = ScanStageMeasurements.Measure(ScanStageTiming.Hash);
            var second = ScanStageMeasurements.Measure(ScanStageTiming.Content);
            first.Dispose(); second.Dispose();
            using (ScanStageMeasurements.Measure(ScanStageTiming.Hash)) { }
        }
        var stages = recorder.Snapshot().Stages;
        Assert.Equal(2, stages.Single(s => s.Stage == "Hash").Samples);
        Assert.Equal(1, stages.Single(s => s.Stage == "Content").Samples);
    }

    [Fact]
    public void StageWhichEndsAfterItsOwnedSinkCloses_DoesNotRecordLateTelemetry()
    {
        using var recorder = new ScanMeasurementRecorder();
        var sink = recorder.BeginPipelineStages();
        var stage = ScanStageMeasurements.Measure(ScanStageTiming.Hash);
        sink.Dispose(); stage.Dispose();
        Assert.Null(recorder.Snapshot().HashStageMs);
        using (recorder.BeginPipelineStages())
        using (ScanStageMeasurements.Measure(ScanStageTiming.Hash)) { }
        Assert.Equal(1, Assert.Single(recorder.Snapshot().Stages).Samples);
    }

    [Fact]
    public void ManyAttempts_KeepAggregatesBoundedWithoutPerFileHistory()
    {
        using var recorder = new ScanMeasurementRecorder();
        string path = InertPath();
        for (int index = 0; index < 1000; index++)
        {
            using var attempt = recorder.Begin(path, Stopwatch.GetTimestamp());
            using (ScanStageMeasurements.Measure(ScanStageTiming.Hash)) { }
            attempt.Complete(FileScanOutcome.Success, true);
        }
        var summary = recorder.Snapshot();
        Assert.Equal(1000, Assert.Single(summary.Volumes).FinishedAttempts);
        Assert.Equal(1000, Assert.Single(summary.Stages).Samples);
        Assert.Null(summary.ContentStageMs);
    }

    [Fact]
    public async Task ManualQueue_PreservesOperationalAndCoverageCounts()
    {
        using var resources = new InertResources();
        using var queue = new ScanQueueCoordinator(resources);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var results = new[]
        {
            new FileScanDetailedResult { Outcome = FileScanOutcome.Success, InspectionComplete = true, IsFromCache = true },
            new FileScanDetailedResult { Outcome = FileScanOutcome.Success, IsSignedClean = true },
            new FileScanDetailedResult { Outcome = FileScanOutcome.Failed, InspectionComplete = false },
            new FileScanDetailedResult { Outcome = FileScanOutcome.Failed },
            new FileScanDetailedResult { Outcome = FileScanOutcome.Timeout, InspectionComplete = false },
            new FileScanDetailedResult { Outcome = FileScanOutcome.Skipped }
        };
        string parent = Path.GetDirectoryName(InertPath())!;
        await queue.ExecuteScanQueueDetailedAsync(parent, ScanType.Custom,
            async enqueue => { for (int index = 0; index < results.Length; index++) await enqueue(Path.Combine(parent, index + ".txt")); },
            (path, _) => Task.FromResult(results[int.Parse(Path.GetFileNameWithoutExtension(path))]), [], (_, _, _, _, _, _) => { }, deadline.Token);
        var volume = Assert.Single(queue.LastMeasurements!.Volumes);
        Assert.Equal(6, volume.FinishedAttempts);
        Assert.Equal(2, volume.SuccessfulAttempts);
        Assert.Equal(2, volume.FailedAttempts);
        Assert.Equal(1, volume.TimedOutAttempts);
        Assert.Equal(1, volume.SkippedAttempts);
        Assert.Equal(0, volume.InterruptedAttempts);
        Assert.Equal(1, volume.CompleteCoverageAttempts);
        Assert.Equal(2, volume.PartialCoverageAttempts);
        Assert.Equal(3, volume.UnknownCoverageAttempts);
        Assert.Equal(1, volume.CachedAttempts);
        Assert.Equal(1, volume.PolicyBypassedAttempts);
        Assert.Null(volume.OutputQueueP95UpperBoundMs);
    }

    private sealed class InertResources : IScanResourceManager, IDisposable
    {
        private readonly SemaphoreSlim _gate = new(1, 1);
        public ScanResourceMode CurrentMode => ScanResourceMode.Low;
        public ScanResourceProfile ActiveProfile { get; } = new() { Concurrency = 1, MaximumConcurrency = 1, ChannelCapacity = 16 };
        public event Action<ScanResourceProfile>? ProfileChanged { add { } remove { } }
        public void SetMode(ScanResourceMode mode) { }
        public Task EnterWorkerSlotAsync(CancellationToken token) => _gate.WaitAsync(token);
        public void ExitWorkerSlot() => _gate.Release();
        public Task ApplyPacingAsync(int count, CancellationToken token) => Task.CompletedTask;
        public void RefreshProfile() { }
        public void Dispose() => _gate.Dispose();
    }
}
