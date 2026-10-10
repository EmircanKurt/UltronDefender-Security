using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using Xunit;

namespace AegisPC.Tests;

public sealed class DetectionReviewFixTests
{
    [Fact]
    public async Task SeveralHeuristics_NeverBecomeAutomaticQuarantineEvidence()
    {
        var hub = new DetectionHub();
        hub.RegisterDetector(new TestDetector("heuristics", _ => Task.FromResult<IEnumerable<SecurityEvidence>>(
            new[] { EvidenceCategory.AntiEvasion, EvidenceCategory.Persistence, EvidenceCategory.StaticApi }
                .Select(c => new SecurityEvidence { Category = c, RuleName = c.ToString(), ScoreContribution = 80, Confidence = EvidenceConfidence.High }))));
        var result = await hub.EvaluateAsync(new DetectionContext { FilePath = "benign-fixture.exe" });
        Assert.True(result.RiskScore >= 85);
        Assert.Equal(DetectionVerdict.HighRisk, result.Verdict);
        Assert.Equal(DetectionPolicy.Warn, result.RecommendedPolicy);
    }

    [Fact]
    public async Task FailedDetector_IsUnknownRatherThanClean()
    {
        var hub = new DetectionHub();
        hub.RegisterDetector(new TestDetector("failure", _ => throw new InvalidOperationException("Synthetic test failure")));
        var result = await hub.EvaluateAsync(new DetectionContext());
        Assert.False(result.IsComplete);
        Assert.Equal(1, result.FailedDetectorCount);
        Assert.Equal(DetectionVerdict.Unknown, result.Verdict);
        Assert.Equal(DetectionPolicy.Observe, result.RecommendedPolicy);
    }

    [Fact]
    public async Task NoActiveDetectors_IsNotACompletedCleanScan()
    {
        var result = await new DetectionHub().EvaluateAsync(new DetectionContext());
        Assert.False(result.IsComplete);
        Assert.Equal(DetectionVerdict.Unknown, result.Verdict);
        Assert.NotEmpty(result.CoverageLimitations);
    }

    [Fact]
    public async Task ConcurrentEvaluations_HaveIndependentFailureCounts()
    {
        var hub = new DetectionHub();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        hub.RegisterDetector(new TestDetector("conditional", async context =>
        {
            if (context.FilePath == "failure")
            {
                entered.SetResult();
                await release.Task;
                throw new InvalidOperationException("Synthetic failure");
            }
            return Array.Empty<SecurityEvidence>();
        }));
        var failed = hub.EvaluateAsync(new DetectionContext { FilePath = "failure" });
        await entered.Task;
        var clean = await hub.EvaluateAsync(new DetectionContext { FilePath = "clean" });
        release.SetResult();
        Assert.True(clean.IsComplete);
        Assert.Equal(0, clean.FailedDetectorCount);
        Assert.Equal(1, (await failed).FailedDetectorCount);
    }

    [Fact]
    public async Task SharedContext_VerifiesSignatureOnceAcrossConcurrentConsumers()
    {
        var verifier = new CountingVerifier();
        var context = new ScanContext("benign-fixture.exe");
        await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => context.GetOrVerifySignatureAsync(verifier)));
        Assert.Equal(1, verifier.Calls);
        Assert.Same(context, context.ToDetectionContext().SharedScan);
    }

    private sealed class CountingVerifier : ISignatureVerifier
    {
        public int Calls;
        public async Task<SignatureInfo> VerifySignatureAsync(string path, CancellationToken ct = default)
        { Interlocked.Increment(ref Calls); await Task.Yield(); return new SignatureInfo(); }
    }

    private sealed class TestDetector(string id, Func<DetectionContext, Task<IEnumerable<SecurityEvidence>>> evaluate) : IDetectorPlugin
    {
        public string DetectorId => id;
        public string DisplayName => id;
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticApi;
        public int Priority => 1;
        public bool IsEnabled { get; set; } = true;
        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken ct = default) => evaluate(context);
    }
}
