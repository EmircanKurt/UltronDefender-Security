using System;
using System.Collections.Generic;
using System.Reflection;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Scanning;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Uses a private, restored in-memory signature fixture; no IOC feed or physical malware is created.</summary>
[Collection("SequentialDiskTests")]
public sealed class ExclusionDetectionPriorityTests
{
    [Fact]
    public async Task ExactKnownHash_IsEvaluatedEvenInsideExcludedPath()
    {
        const string hash = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";
        var detector = new FixtureDetector();
        try
        {
            await new DetectionHub(new[] { detector }, exclusionService: new ExcludesEverything())
                .EvaluateAsync(new DetectionContext { FilePath = "inert-fixture", SHA256 = hash });
            Assert.Equal(1, detector.Calls);
        }
        finally { /* No mutable signature fixture or payload was created. */ }
    }

    [Fact]
    public async Task Cancellation_IsNotBypassedByExcludedPath()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new DetectionHub(exclusionService: new ExcludesEverything())
            .EvaluateAsync(new DetectionContext { FilePath = "inert-fixture" }, cancellation.Token));
    }

    [Fact]
    public async Task RealTime_ExcludedPathCannotHideExactKnownContent()
    {
        string path = Path.Combine(Path.GetTempPath(), "Ultron_InertPriority_" + Guid.NewGuid().ToString("N") + ".dat");
        byte[] bytes = Encoding.UTF8.GetBytes("inert real-time exclusion priority fixture");
        await File.WriteAllBytesAsync(path, bytes);
        try
        {
            var processor = new RealTimeVerdictProcessor(new SimulatedTestMarkerHash(), new SignatureVerifier(), new RiskScoringEngine(),
                fileHashMatcher: null, reputationService: null, exclusionService: new ExcludesEverything());
            var result = await processor.InspectFileAsync(path);
            Assert.Equal(AegisPC.Core.Enums.RealTimeVerdict.ConfirmedMalicious, result.Verdict);
        }
        finally { File.Delete(path); }
    }

    private sealed class SimulatedTestMarkerHash : IHashService
    {
        // Inert workflow stub, not a real sample or a detection efficacy test.
        public Task<string> ComputeSha256Async(string path, CancellationToken ct = default) =>
            Task.FromResult("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F");
        public Task<string> ComputeSha1Async(string path, CancellationToken ct = default) => Task.FromResult(new string('A', 40));
    }

    private sealed class FixtureDetector : IDetectorPlugin
    {
        public int Calls;
        public string DetectorId => "InertFixture";
        public string DisplayName => "InertFixture";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticSignature;
        public int Priority => 1;
        public bool IsEnabled { get; set; } = true;
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken ct = default)
        { Calls++; return Task.FromResult<IEnumerable<SecurityEvidence>>(Array.Empty<SecurityEvidence>()); }
    }

    private sealed class ExcludesEverything : IExclusionService
    {
        public bool IsExcluded(string? path, string? hash = null) => true;
        public Task<bool> IsExcludedAsync(string? path, string? hash = null, CancellationToken ct = default) => Task.FromResult(true);
        public Task<IReadOnlyList<ExclusionEntry>> GetAllExclusionsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ExclusionEntry> AddPathExclusionAsync(string path, bool sub = true, string? reason = null, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ExclusionEntry> AddSha256ExclusionAsync(string hash, string? reason = null, CancellationToken ct = default) => throw new NotSupportedException();
        public void AddTemporaryPathExclusion(string path, TimeSpan duration, string? reason = null) => throw new NotSupportedException();
        public Task<bool> RemoveExclusionAsync(int id, CancellationToken ct = default) => throw new NotSupportedException();
        public bool IsRootOrSystemDirectory(string path) => false;
        public Task InitializeAsync(CancellationToken ct = default) => Task.CompletedTask;
    }
}

