using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Kernel;
using AegisPC.Contracts.Services;
using AegisPC.Security.Kernel;
using AegisPC.Service.DriverBridge;
using Xunit;
using LegacyRequest = AegisPC.Infrastructure.Kernel.KernelIpcService.ScanRequest;
using LegacyTransport = AegisPC.Infrastructure.Kernel.KernelIpcService;

namespace AegisPC.Tests;

/// <summary>Inert decision and source guard tests. No driver, live ETW, service, certificate store or boot changes occur.</summary>
[Collection("SequentialDiskTests")]
public sealed class UltronFilterReviewTests
{
    [Theory]
    [InlineData(0u, 1u, (byte)0, true)]
    [InlineData(0u, 1u, (byte)1, true)]
    [InlineData(0x102u, 1u, (byte)1, false)]
    [InlineData(0xC0000022u, 1u, (byte)1, false)]
    [InlineData(0u, 0u, (byte)1, false)]
    [InlineData(0u, 2u, (byte)1, false)]
    [InlineData(0u, 1u, (byte)2, false)]
    [InlineData(0u, 1u, (byte)255, false)]
    public void TimeoutMalformedAndNoncanonicalRepliesCannotBeSuccessfulReplies(uint status, uint bytes, byte value, bool expected)
        => Assert.Equal(expected, UltronFilterPilotPolicy.IsValidLegacyReply(status, bytes, value));

    [Fact]
    public void ExperimentalSwitchCannotActivateLegacyBridgeOrListener()
    {
        Assert.False(UltronFilterPilotPolicy.IdentityBoundEnforcementAvailable);
        Assert.False(UltronFilterPilotPolicy.LegacyBridgeActivationAllowed);
        using var bridge = new KernelBridge();
        Assert.False(bridge.StartBridge());
        Assert.False(bridge.IsDriverConnected);
        Assert.False(bridge.IsEnforcementActive);
        using var legacy = new LegacyTransport();
        Assert.False(legacy.RegisterProtectedProcess((uint)Environment.ProcessId));
        Assert.Throws<NotSupportedException>(() => legacy.StartListener(_ => true));
    }

    [Fact]
    public async Task ExistingBenignFileAndSyntheticAbsoluteEvidenceRemainReviewWithoutNativeAction()
    {
        using var fixture = new InertFile();
        var hub = new SyntheticHub(fixture.Path);
        var gate = new KernelGatingEngine(detectionHub: hub);
        var decision = await gate.EvaluatePreOpDecisionAsync(new KernelIpcMessage
        {
            FilePath = fixture.Path, ProcessId = 12345, OpCode = MinifilterOperationType.PreCreate, TimeoutMs = 5000
        });
        Assert.Equal(1, hub.Calls);
        Assert.False(decision.IsBlocked);
        Assert.False(decision.ShouldQuarantine);
        Assert.Equal(0u, decision.NtStatus);
        Assert.Contains("no block occurred", decision.BlockReason);
        Assert.Equal(InertFile.Content, File.ReadAllText(fixture.Path));
    }

    [Fact]
    public void LegacyProposalCannotPublishBlockedAuditFindingOrQuarantine()
    {
        using var fixture = new InertFile();
        var findings = DispatchProxy.Create<ISecurityFindingService, ForbiddenActionProxy>();
        var audit = DispatchProxy.Create<IAuditLogService, ForbiddenActionProxy>();
        var quarantine = DispatchProxy.Create<IQuarantineService, ForbiddenActionProxy>();
        var hub = new SyntheticHub(fixture.Path);
        using var bridge = new KernelBridge(detectionHub: hub, findingService: findings,
            auditLogService: audit, quarantineService: quarantine);
        Assert.False(bridge.EvaluateKernelScanRequest(new LegacyRequest { FilePath = fixture.Path, ProcessId = 12345 }));
        Assert.Equal(1, hub.Calls);
        Assert.Equal(0, ((ForbiddenActionProxy)(object)findings).Calls);
        Assert.Equal(0, ((ForbiddenActionProxy)(object)audit).Calls);
        Assert.Equal(0, ((ForbiddenActionProxy)(object)quarantine).Calls);
    }

    [Fact]
    public async Task PreWriteNeverScansOldPathAsIncomingWriteContent()
    {
        using var fixture = new InertFile();
        var hub = new SyntheticHub(fixture.Path);
        using var bridge = new KernelBridge(detectionHub: hub);
        Assert.False(bridge.EvaluateKernelScanRequest(new LegacyRequest
            { FilePath = fixture.Path, ProcessId = 12345, IsWriteOperation = true }));
        var result = await new KernelGatingEngine(detectionHub: hub).EvaluatePreOpDecisionAsync(new KernelIpcMessage
            { FilePath = fixture.Path, ProcessId = 12345, OpCode = MinifilterOperationType.PreWrite });
        Assert.Equal(0, hub.Calls);
        Assert.False(result.IsBlocked);
        Assert.Contains("Incoming write content is unavailable", result.BlockReason);
    }

    [Fact]
    public async Task CallerCancellationIsNotReportedAsNativeTimeoutOrAttack()
    {
        using var fixture = new InertFile();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var gate = new KernelGatingEngine();
        var result = await gate.EvaluatePreOpDecisionAsync(new KernelIpcMessage
            { FilePath = fixture.Path, ProcessId = 12345 }, cancellation.Token);
        Assert.False(result.IsBlocked);
        Assert.Equal(0, gate.TimeoutFallbackCount);
        Assert.Contains("cancelled by the caller", result.BlockReason);
    }

    [Fact]
    public void NativePilotValidatesExactRepliesAndDoesNotMutateAccessStatus()
    {
        var native = Source("drivers/AegisFilter/AegisFilter.c");
        var framing = Source("drivers/AegisFilter/UltronFilterPilotSafety.h");
        Assert.Contains("status == STATUS_SUCCESS", framing);
        Assert.Contains("replyBytes == sizeof(BOOLEAN)", framing);
        Assert.DoesNotContain("NT_SUCCESS(status) && scanResp", native);
        Assert.DoesNotContain("STATUS_ACCESS_DENIED", native);
        Assert.Contains("return STATUS_NOT_SUPPORTED;", native);
        Assert.DoesNotContain("gProtectedPid = cmd->ProcessId", native);
        var writeStart = native.LastIndexOf("FLT_PREOP_CALLBACK_STATUS AegisPreWrite(", StringComparison.Ordinal);
        var writeEnd = native.IndexOf("FLT_POSTOP_CALLBACK_STATUS AegisPostCreate(", writeStart, StringComparison.Ordinal);
        Assert.DoesNotContain("FltSendMessage", native[writeStart..writeEnd]);
        Assert.DoesNotContain("PAGED_CODE", native[writeStart..writeEnd]);
    }

    [Theory]
    [InlineData("drivers/AegisFilter/AegisFilter.inf")]
    [InlineData("drivers/AegisPC.Driver/AegisDriver.inf")]
    public void DriverTemplatesCannotReuseSomeOtherVendorsAssignedAltitude(string path)
    {
        var inf = Source(path);
        Assert.Contains("UNASSIGNED", inf);
        Assert.DoesNotContain("320500", inf);
        Assert.DoesNotContain("385100", inf);
    }

    [Fact]
    public void BuildPipelineFailsOnNativeErrorsAndNeverChangesHostTrustOrBootPolicy()
    {
        var script = Source("drivers/Build-And-Sign-Driver.ps1");
        Assert.Contains("$LASTEXITCODE -ne 0", script);
        Assert.Contains("throw \"Catalog generation", script);
        Assert.Contains("AltitudeAssignmentEvidencePath", script);
        Assert.Contains("ReleaseApproved = $false", script);
        Assert.Contains("\"verify\", \"/kp\"", script);
        Assert.DoesNotContain("New-SelfSignedCertificate", script);
        Assert.DoesNotContain("X509Store", script);
        Assert.DoesNotContain("Cert:\\LocalMachine", script);
        Assert.DoesNotContain("fltmc load", script);
        Assert.DoesNotContain("bcdedit", script);
        Assert.DoesNotContain("Continuing without catalog", script);
        foreach (var wrapper in new[] { "drivers/build_and_sign_driver.bat", "drivers/build_driver.cmd" })
        {
            var content = Source(wrapper);
            Assert.Contains("Build-And-Sign-Driver.ps1", content);
            Assert.DoesNotContain("New-SelfSignedCertificate", content);
            Assert.DoesNotContain("bcdedit", content);
        }
    }

    private static string Source(string relative)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(System.IO.Path.Combine(directory.FullName, "AegisPC.sln")))
            directory = directory.Parent;
        return File.ReadAllText(System.IO.Path.Combine(directory?.FullName
            ?? throw new DirectoryNotFoundException("Test checkout not found."), relative));
    }

    public class ForbiddenActionProxy : DispatchProxy
    {
        public int Calls { get; private set; }
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            Calls++;
            throw new InvalidOperationException("A path-only review must never invoke an action/persistence service.");
        }
    }

    private sealed class InertFile : IDisposable
    {
        internal const string Content = "BENIGN ULTRON FILTER REVIEW FIXTURE. This is not malware or an AV test signature.";
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ultron-filter-review-" + Guid.NewGuid().ToString("N") + ".bin");
        internal InertFile() => File.WriteAllText(Path, Content);
        public void Dispose() => File.Delete(Path);
    }

    private sealed class SyntheticHub(string path) : IDetectionHub
    {
        internal int Calls;
        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => Array.Empty<IDetectorPlugin>();
        public void RegisterDetector(IDetectorPlugin detector) => throw new NotSupportedException();
        public bool UnregisterDetector(string detectorId) => false;
        public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(new DetectionResult
            {
                Verdict = DetectionVerdict.ConfirmedMalicious, RiskScore = 100,
                SHA256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))), ThreatTitle = "Synthetic review evidence, not malware",
                Evidences = new List<SecurityEvidence> { new()
                    { Category = EvidenceCategory.StaticSignature, Confidence = EvidenceConfidence.Absolute, ScoreContribution = 100 } }
            });
        }
    }
}
