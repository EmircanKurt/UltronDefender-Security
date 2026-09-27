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
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("inert Ultron exclusion priority fixture")));
        var table = (Dictionary<string, (string, string, int, string)>)typeof(MalwareSignatureDatabase)
            .GetField("KnownThreatHashes", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        var detector = new FixtureDetector();
        table.Add(hash, ("Inert test-only fixture", "Test", 100, "2026-09-27"));
        try
        {
            await new DetectionHub(new[] { detector }, exclusionService: new ExcludesEverything())
                .EvaluateAsync(new DetectionContext { FilePath = "inert-fixture", SHA256 = hash });
            Assert.Equal(1, detector.Calls);
        }
        finally { table.Remove(hash); }
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
        string hash = Convert.ToHexString(SHA256.HashData(bytes));
        var table = (Dictionary<string, (string, string, int, string)>)typeof(MalwareSignatureDatabase)
            .GetField("KnownThreatHashes", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        await File.WriteAllBytesAsync(path, bytes);
        table.Add(hash, ("Inert test-only fixture", "Test", 100, "2026-09-27"));
        try
        {
            var processor = new RealTimeVerdictProcessor(new HashService(), new SignatureVerifier(), new RiskScoringEngine(),
                fileHashMatcher: null, reputationService: null, exclusionService: new ExcludesEverything());
            var result = await processor.InspectFileAsync(path);
            Assert.Equal(AegisPC.Core.Enums.RealTimeVerdict.ConfirmedMalicious, result.Verdict);
        }
        finally { table.Remove(hash); File.Delete(path); }
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
