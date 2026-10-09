using System.Diagnostics;
using System.IO;
using System.Text;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Connects measured coverage to actual inert manual inspection; no containment or live protection.</summary>
public sealed class ReviewStageOnePipelineTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ManualTrustPolicy_DoesNotConfuseSuccessWithDeepInspection(bool allowlisted)
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("ordinary.txt", Encoding.UTF8.GetBytes("An ordinary local synthetic note."));
        string originalHash = await fixture.ComputeInputIdentityAsync(path);
        var hub = new CountingHub(fixture.CreateHub());
        using var resources = new InertResources();
        using var queue = new ScanQueueCoordinator(resources);
        var scanner = new FileScannerService(new DirectoryWalker(), queue,
            new FileHashMatcher(fixture.HashService, fixture.SignatureVerifier, new InertAllowlist(allowlisted)),
            new PupAnalysisCoordinator(hub), new ArchiveSafetyScanner());
        using var measurements = new ScanMeasurementRecorder();
        using (var attempt = measurements.Begin(path, Stopwatch.GetTimestamp()))
        {
            var result = await scanner.ScanFileDetailedAsync(path, TimeSpan.FromSeconds(5));
            Assert.Equal(FileScanOutcome.Success, result.Outcome);
            Assert.Equal(!allowlisted, result.InspectionComplete);
            Assert.Equal(allowlisted, result.IsSignedClean);
            Assert.True(result.ContentClassification!.IsComplete);
            attempt.Complete(result);
        }
        var volume = Assert.Single(measurements.Snapshot().Volumes);
        Assert.Equal(1, volume.SuccessfulAttempts);
        Assert.Equal(allowlisted ? 0 : 1, volume.CompleteCoverageAttempts);
        Assert.Equal(allowlisted ? 1 : 0, volume.PartialCoverageAttempts);
        Assert.Equal(allowlisted ? 1 : 0, volume.PolicyBypassedAttempts);
        Assert.Equal(allowlisted ? 0 : 1, hub.Calls);
        Assert.Equal(originalHash, await fixture.ComputeInputIdentityAsync(path));
    }

    [Fact]
    public async Task OpaqueContent_PreservesIncompleteCoverageAndInput()
    {
        using var fixture = ReviewStageOneFixture.Create();
        string path = fixture.WriteInput("opaque.bin", Enumerable.Repeat((byte)0xff, 1024).ToArray());
        string originalHash = await fixture.ComputeInputIdentityAsync(path);
        using var resources = new InertResources();
        using var queue = new ScanQueueCoordinator(resources);
        var scanner = new FileScannerService(new DirectoryWalker(), queue,
            new FileHashMatcher(fixture.HashService, fixture.SignatureVerifier, new InertAllowlist(false)),
            new PupAnalysisCoordinator(fixture.CreateHub()), new ArchiveSafetyScanner());
        using var measurements = new ScanMeasurementRecorder();
        using (var attempt = measurements.Begin(path, Stopwatch.GetTimestamp()))
        {
            var result = await scanner.ScanFileDetailedAsync(path, TimeSpan.FromSeconds(5));
            Assert.Equal(FileScanOutcome.Failed, result.Outcome);
            Assert.False(result.InspectionComplete);
            Assert.Null(result.Finding);
            attempt.Complete(result);
        }
        var volume = Assert.Single(measurements.Snapshot().Volumes);
        Assert.Equal(1, volume.FailedAttempts);
        Assert.Equal(1, volume.PartialCoverageAttempts);
        Assert.Equal(0, volume.CompleteCoverageAttempts);
        Assert.Equal(originalHash, await fixture.ComputeInputIdentityAsync(path));
    }

    private sealed class CountingHub(IDetectionHub actual) : IDetectionHub
    {
        internal int Calls;
        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => actual.RegisteredDetectors;
        public void RegisterDetector(IDetectorPlugin detector) => throw new InvalidOperationException();
        public bool UnregisterDetector(string detectorId) => throw new InvalidOperationException();
        public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Calls);
            return actual.EvaluateAsync(context, cancellationToken);
        }
    }

    private sealed class InertAllowlist(bool allowlisted) : IAllowlistService
    {
        public bool IsAllowlisted(string hash) => allowlisted;
        public bool IsPathAllowlisted(string path) => false;
        public Task<bool> IsAllowlistedAsync(string hash, CancellationToken ct = default) => Task.FromResult(allowlisted);
        public Task<bool> IsPathAllowlistedAsync(string path, CancellationToken ct = default) => Task.FromResult(false);
        public Task AddToAllowlistAsync(AllowlistEntry entry, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task RemoveFromAllowlistAsync(int id, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<List<AllowlistEntry>> GetAllowlistAsync(CancellationToken ct = default) => Task.FromResult(new List<AllowlistEntry>());
        public Task<bool> CheckHashChangedAsync(AllowlistEntry entry, CancellationToken ct = default) => Task.FromResult(false);
    }

    private sealed class InertResources : IScanResourceManager, IDisposable
    {
        public ScanResourceMode CurrentMode => ScanResourceMode.Low;
        public ScanResourceProfile ActiveProfile { get; } = new() { Concurrency = 1, MaximumConcurrency = 1, ChannelCapacity = 16 };
        public event Action<ScanResourceProfile>? ProfileChanged { add { } remove { } }
        public void SetMode(ScanResourceMode mode) { }
        public Task EnterWorkerSlotAsync(CancellationToken ct) => Task.CompletedTask;
        public void ExitWorkerSlot() { }
        public Task ApplyPacingAsync(int count, CancellationToken ct) => Task.CompletedTask;
        public void RefreshProfile() { }
        public void Dispose() { }
    }
}

