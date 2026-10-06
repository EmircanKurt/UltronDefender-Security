using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Kernel;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Kernel;
using AegisPC.Security.RealTime;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using AegisPC.Service.DriverBridge;
using Xunit;

namespace AegisPC.Tests;

[Collection("SequentialDiskTests")]
public sealed class SelfPathTrustBoundaryTests : IDisposable
{
    private readonly string _root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
        "self-path-safety-" + Guid.NewGuid().ToString("N"));
    private readonly string _file;

    public SelfPathTrustBoundaryTests()
    {
        Directory.CreateDirectory(_root);
        _file = Path.Combine(_root, "benign-fixture.exe");
        File.WriteAllText(_file, "BENIGN SELF PATH TRUST BOUNDARY FIXTURE");
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public async Task WritableApplicationRootIsQueuedAndInspectedInsteadOfPathTrusted()
    {
        Assert.True(ScanFilterPolicy.IsInspectableCandidate(_file));

        var queued = new List<string>();
        await new DirectoryWalker().EnumerateDirectorySafelyAsync(
            _root, recursive: true,
            path => { queued.Add(path); return Task.CompletedTask; },
            CancellationToken.None);
        Assert.Contains(_file, queued);

        var hash = new FailingHashService();
        var verdict = await new RealTimeVerdictProcessor(hash, new UnusedSignatureVerifier(),
            new UnusedRiskScoringEngine()).InspectFileAsync(_file);
        Assert.Equal(1, hash.CallCount);
        Assert.Equal(RealTimeVerdict.Unknown, verdict.Verdict);
        Assert.Equal(RealTimePolicyAction.Observe, verdict.RecommendedPolicy);
    }

    [Fact]
    public void ProductStateRemainsGuardedAgainstDestructiveActions()
    {
        var state = new ProtectedPathGuard().Evaluate(_file);
        Assert.True(state.IsProtected);
        Assert.False(state.IsCriticalSystemCore);
    }

    [Theory]
    [InlineData(Environment.SpecialFolder.LocalApplicationData)]
    [InlineData(Environment.SpecialFolder.ApplicationData)]
    [InlineData(Environment.SpecialFolder.CommonApplicationData)]
    public void WritableProductDataDirectoryIsNotAnAutomaticScanExclusion(
        Environment.SpecialFolder folder)
    {
        string root = Environment.GetFolderPath(folder);
        Assert.False(string.IsNullOrWhiteSpace(root));
        string candidate = Path.Combine(root, "UltronDefender", "untrusted-file.exe");
        Assert.True(ScanFilterPolicy.IsInspectableCandidate(candidate));
    }

    [Theory]
    [InlineData(DetectionVerdict.Suspicious, 95)]
    [InlineData(DetectionVerdict.ConfirmedMalicious, 100)]
    public async Task KernelGatingInspectsApplicationRootWithoutScoreOnlyAction(
        DetectionVerdict verdict, int riskScore)
    {
        var hub = new FakeDetectionHub(new DetectionResult
        {
            Verdict = verdict,
            RiskScore = riskScore,
            SHA256 = null,
            ThreatTitle = "Synthetic review signal"
        });
        var gate = new KernelGatingEngine(detectionHub: hub);
        var decision = await gate.EvaluatePreOpDecisionAsync(new KernelIpcMessage
        {
            FilePath = _file,
            ProcessId = 12345,
            TimeoutMs = 5000
        });

        Assert.Equal(1, hub.CallCount);
        Assert.False(decision.IsBlocked);
        Assert.False(decision.ShouldQuarantine);
    }

    [Theory]
    [InlineData(DetectionVerdict.Suspicious, 95)]
    [InlineData(DetectionVerdict.ConfirmedMalicious, 100)]
    public void KernelBridgeInspectsApplicationRootWithoutScoreOnlyAction(
        DetectionVerdict verdict, int riskScore)
    {
        var hub = new FakeDetectionHub(new DetectionResult
        {
            Verdict = verdict,
            RiskScore = riskScore,
            SHA256 = null,
            ThreatTitle = "Synthetic review signal"
        });
        using var bridge = new KernelBridge(detectionHub: hub);
        bool blocked = bridge.EvaluateKernelScanRequest(new AegisPC.Infrastructure.Kernel.KernelIpcService.ScanRequest
        {
            FilePath = _file,
            ProcessId = 12345
        });

        Assert.Equal(1, hub.CallCount);
        Assert.False(blocked);
    }

    [Fact]
    public async Task KernelGatingObservesHashBoundEvidenceWithoutUnverifiedNativeEnforcement()
    {
        string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(_file)));
        var hub = new FakeDetectionHub(new DetectionResult
        {
            Verdict = DetectionVerdict.ConfirmedMalicious,
            RiskScore = 100,
            SHA256 = hash,
            ThreatTitle = "Synthetic absolute signature",
            Evidences = new List<SecurityEvidence>
            {
                new() { Category = EvidenceCategory.StaticSignature,
                    Confidence = EvidenceConfidence.Absolute, ScoreContribution = 100 }
            }
        });
        var gate = new KernelGatingEngine(detectionHub: hub);
        var decision = await gate.EvaluatePreOpDecisionAsync(new KernelIpcMessage
        {
            FilePath = _file,
            ProcessId = 12345,
            TimeoutMs = 5000
        });

        Assert.Equal(1, hub.CallCount);
        Assert.False(decision.IsBlocked);
        Assert.Contains("no block occurred", decision.BlockReason);
        Assert.False(decision.ShouldQuarantine);
    }

    private sealed class FailingHashService : IHashService
    {
        public int CallCount { get; private set; }

        public Task<string> ComputeSha256Async(string filePath, CancellationToken cancellationToken = default)
        {
            CallCount++;
            throw new IOException("Synthetic hash failure before any verdict can be established.");
        }

        public Task<string> ComputeSha1Async(string filePath, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class UnusedSignatureVerifier : ISignatureVerifier
    {
        public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class UnusedRiskScoringEngine : IRiskScoringEngine
    {
        public Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(
            FileAnalysisResult result, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class FakeDetectionHub : IDetectionHub
    {
        private readonly DetectionResult _result;
        public int CallCount { get; private set; }
        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => Array.Empty<IDetectorPlugin>();

        public FakeDetectionHub(DetectionResult result) => _result = result;

        public void RegisterDetector(IDetectorPlugin detector) => throw new NotSupportedException();
        public bool UnregisterDetector(string detectorId) => false;

        public Task<DetectionResult> EvaluateAsync(DetectionContext context,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult(_result);
        }
    }
}
