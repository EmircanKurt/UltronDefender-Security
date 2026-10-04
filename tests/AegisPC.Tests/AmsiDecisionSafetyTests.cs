using System;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Tests AMSI decisions through an inert injected adapter; never loads AMSI, registers providers, or modifies Windows.</summary>
public sealed class AmsiDecisionSafetyTests
{
    [Fact]
    public async Task UnavailableProvider_BenignText_IsUnknownNotClean()
    {
        using var service = Service(new InertProvider(available: false));
        var result = await service.ScanStringAsync("Write-Output 'School backup completed'");

        Assert.False(service.IsAmsiSupported);
        Assert.False(result.IsMalicious);
        Assert.False(result.IsComplete);
        Assert.Equal(AmsiDetectionResult.Unknown, result.Result);
        Assert.Equal(AmsiVerdictSource.HeuristicFallback, result.Source);
        Assert.Equal(AmsiNativeScanStatus.Unavailable, result.NativeStatus);
        Assert.Equal(0, result.RawResultCode);
        Assert.Null(result.NativeHResult);
        Assert.False(service.LastNativeRequestCompleted);
        Assert.Null(service.LastNativeScanUtc);
    }

    [Theory]
    [InlineData("Documentation mentions amsiInitFailed", AmsiHeuristicIndicators.DefenseEvasionReference)]
    [InlineData("Manual explains DownloadString and IEX", AmsiHeuristicIndicators.DownloadExecutionReference)]
    [InlineData("Help: vssadmin delete shadows", AmsiHeuristicIndicators.RecoveryTamperingReference)]
    [InlineData("Help: bcdedit recoveryenabled no", AmsiHeuristicIndicators.RecoveryTamperingReference)]
    public async Task KeywordHints_WithoutProvider_AreReviewOnly(string content, AmsiHeuristicIndicators expectedHint)
    {
        using var service = Service(new InertProvider(available: false));
        var result = await service.ScanStringAsync(content);

        Assert.Equal(AmsiDetectionResult.Suspicious, result.Result);
        Assert.Equal(AmsiVerdictSource.HeuristicFallback, result.Source);
        Assert.Equal(expectedHint, result.HeuristicIndicators);
        Assert.False(result.IsMalicious);
        Assert.False(result.IsComplete);
        Assert.Equal(0, result.RawResultCode);
    }

    [Theory]
    [InlineData(0, AmsiDetectionResult.Clean, false)]
    [InlineData(1, AmsiDetectionResult.NotDetected, false)]
    [InlineData(123, AmsiDetectionResult.NotDetected, false)]
    [InlineData(16384, AmsiDetectionResult.BlockedByAdmin, false)]
    [InlineData(20479, AmsiDetectionResult.BlockedByAdmin, false)]
    [InlineData(20480, AmsiDetectionResult.NotDetected, false)]
    [InlineData(32768, AmsiDetectionResult.Malicious, true)]
    [InlineData(32769, AmsiDetectionResult.Malicious, true)]
    public async Task CompletedProviderVerdict_PreservesNativeResultAndPolicyBoundary(
        int raw, AmsiDetectionResult expected, bool malicious)
    {
        var adapter = new InertProvider(raw: raw);
        using var service = Service(adapter);
        var result = await service.ScanStringAsync("Synthetic inspection fixture");

        Assert.True(service.IsAmsiSupported);
        Assert.True(result.IsComplete);
        Assert.Equal(expected, result.Result);
        Assert.Equal(malicious, result.IsMalicious);
        Assert.Equal(AmsiVerdictSource.NativeProvider, result.Source);
        Assert.Equal(AmsiNativeScanStatus.Completed, result.NativeStatus);
        Assert.Equal(0, result.NativeHResult);
        Assert.Equal(raw, result.RawResultCode);
        Assert.Equal(1, adapter.StringRequests);
        Assert.True(service.LastNativeRequestCompleted);
        Assert.NotNull(service.LastNativeScanUtc);
        Assert.Equal(DateTimeKind.Utc, service.LastNativeScanUtc!.Value.Kind);
    }

    [Theory]
    [InlineData(-2147467259, 32768)]
    [InlineData(1, 32768)]
    [InlineData(0, -1)]
    public async Task FailedOrInvalidProviderOutput_CannotProduceMalwareOrCleanVerdict(int hResult, int raw)
    {
        using var service = Service(new InertProvider(hResult: hResult, raw: raw));
        var result = await service.ScanBufferAsync(Encoding.UTF8.GetBytes("ordinary school data"));

        Assert.False(result.IsMalicious);
        Assert.False(result.IsComplete);
        Assert.Equal(AmsiDetectionResult.Unknown, result.Result);
        Assert.Equal(AmsiNativeScanStatus.Failed, result.NativeStatus);
        Assert.Equal(hResult, result.NativeHResult);
        Assert.Equal(0, result.RawResultCode);
        Assert.Equal(AmsiVerdictSource.HeuristicFallback, result.Source);
        Assert.False(service.LastNativeRequestCompleted);
        Assert.Null(service.LastNativeScanUtc);
    }

    [Fact]
    public async Task ProviderException_DoesNotReuseInitializationSuccessAsScanHResult()
    {
        using var service = Service(new InertProvider(throwOnScan: true));
        var result = await service.ScanStringAsync("ordinary school data");

        Assert.Equal(AmsiNativeScanStatus.Failed, result.NativeStatus);
        Assert.Null(result.NativeHResult);
        Assert.Equal(AmsiDetectionResult.Unknown, result.Result);
        Assert.False(result.IsComplete);
        Assert.False(result.IsMalicious);
    }

    [Fact]
    public async Task NativeCleanWithHeuristicReferences_RemainsExplicitNativeCleanWithSeparateHints()
    {
        using var service = Service(new InertProvider(raw: 0));
        var result = await service.ScanStringAsync("Documentation: amsiInitFailed, IEX and DownloadString");

        Assert.Equal(AmsiDetectionResult.Clean, result.Result);
        Assert.Equal(AmsiVerdictSource.NativeProvider, result.Source);
        Assert.True(result.IsComplete);
        Assert.False(result.IsMalicious);
        Assert.True(result.HeuristicIndicators.HasFlag(AmsiHeuristicIndicators.DefenseEvasionReference));
        Assert.True(result.HeuristicIndicators.HasFlag(AmsiHeuristicIndicators.DownloadExecutionReference));
    }

    [Fact]
    public async Task EmbeddedNull_StringUsesLengthAwareBufferWithoutDroppingSuffix()
    {
        const string input = "School\0suffix is still inspected";
        var adapter = new InertProvider(raw: 1);
        using var service = Service(adapter);
        var result = await service.ScanStringAsync(input);

        Assert.True(result.IsComplete);
        Assert.Equal(0, adapter.StringRequests);
        Assert.Equal(1, adapter.BufferRequests);
        Assert.Equal(Encoding.Unicode.GetBytes(input), adapter.LastBuffer);
    }

    [Fact]
    public async Task CanonicalWorkflowTestSignature_CannotBeErasedByNativeClean()
    {
        using var service = Service(new InertProvider(raw: 0));
        var result = await service.ScanBufferAsync(CanonicalWorkflowTestBytes());

        Assert.True(result.IsMalicious);
        Assert.Equal(AmsiDetectionResult.Malicious, result.Result);
        Assert.Equal(AmsiVerdictSource.CanonicalTestSignature, result.Source);
        Assert.Equal(AmsiNativeScanStatus.Completed, result.NativeStatus);
        Assert.True(result.IsComplete);
        Assert.Equal(0, result.RawResultCode); // Actual native result is not replaced with a fabricated native malware code.
        Assert.False(service.LastNativeRequestCompleted);
        Assert.Null(service.LastNativeScanUtc);
    }

    [Fact]
    public async Task CanonicalWorkflowTestSignature_WithUnavailableProvider_IsNotCompletedNativeInspection()
    {
        using var service = Service(new InertProvider(available: false));
        var result = await service.ScanBufferAsync(CanonicalWorkflowTestBytes());

        Assert.True(result.IsMalicious);
        Assert.Equal(AmsiVerdictSource.CanonicalTestSignature, result.Source);
        Assert.Equal(AmsiNativeScanStatus.Unavailable, result.NativeStatus);
        Assert.False(result.IsComplete);
        Assert.Equal(0, result.RawResultCode);
    }

    [Fact]
    public async Task TestSignatureQuotedInDocumentation_IsNotAnExactFallbackSignature()
    {
        using var service = Service(new InertProvider(available: false));
        string documentation = "Documentation quotes: " + Encoding.ASCII.GetString(CanonicalWorkflowTestBytes());
        var result = await service.ScanStringAsync(documentation);

        Assert.False(result.IsMalicious);
        Assert.Equal(AmsiDetectionResult.Unknown, result.Result);
        Assert.Equal(AmsiVerdictSource.HeuristicFallback, result.Source);
    }

    [Fact]
    public async Task EmptyInput_IsDistinguishedFromProviderInspection()
    {
        var adapter = new InertProvider();
        using var service = Service(adapter);
        var result = await service.ScanStringAsync(string.Empty, "empty-fixture");

        Assert.Equal(AmsiVerdictSource.EmptyInput, result.Source);
        Assert.Equal(AmsiNativeScanStatus.NotAttempted, result.NativeStatus);
        Assert.Equal(AmsiDetectionResult.Clean, result.Result);
        Assert.True(result.IsComplete);
        Assert.Equal(0, adapter.StringRequests + adapter.BufferRequests);
        Assert.False(service.LastNativeRequestCompleted);
        Assert.Null(service.LastNativeScanUtc);
    }

    [Fact]
    public async Task ServiceWrapper_PreservesNativeFailureCoverage()
    {
        using var service = new AegisPC.Service.Amsi.AmsiScanService(nativeProvider: new InertProvider(hResult: -2147467259, raw: 32768));
        var result = await service.ScanStringAsync("ordinary school data");

        Assert.False(result.IsComplete);
        Assert.False(result.IsMalicious);
        Assert.Equal(AmsiNativeScanStatus.Failed, result.NativeStatus);
        Assert.Equal(AmsiDetectionResult.Unknown, result.Result);
        Assert.False(service.LastNativeRequestCompleted);
        Assert.Null(service.LastNativeScanUtc);
    }

    [Fact]
    public async Task DisposedService_RejectsRequestsInsteadOfClaimingClean()
    {
        var adapter = new InertProvider();
        var service = Service(adapter);
        service.Dispose();
        service.Dispose();

        Assert.False(service.IsAmsiSupported);
        Assert.True(adapter.IsDisposed);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => service.ScanStringAsync("ordinary data"));
    }

    private static AmsiScanService Service(IAmsiNativeProvider adapter) => new(nativeProvider: adapter);

    // The industry workflow reference is assembled only in memory and is never written or executed.
    // These tests prove decision plumbing, not real malware detection efficacy.
    private static byte[] CanonicalWorkflowTestBytes() => Encoding.ASCII.GetBytes(string.Concat(
        "X5O!", "P%@AP[4", "\\PZX54(P^)7CC)7}", "$", "EICAR", "-STANDARD-ANTIVIRUS-TEST-FILE!", "$H+H*"));

    private sealed class InertProvider : IAmsiNativeProvider
    {
        private readonly bool _available;
        private readonly bool _throwOnScan;
        private readonly NativeAmsiScanResponse _response;
        public InertProvider(bool available = true, int hResult = 0, int raw = 1, bool throwOnScan = false)
        { _available = available; _response = new NativeAmsiScanResponse(hResult, raw); _throwOnScan = throwOnScan; }
        public bool IsAvailable => _available && !IsDisposed;
        public int? InitializationHResult => _available ? 0 : null;
        public int StringRequests { get; private set; }
        public int BufferRequests { get; private set; }
        public byte[]? LastBuffer { get; private set; }
        public bool IsDisposed { get; private set; }
        public NativeAmsiScanResponse ScanString(string content, string contentName)
        { StringRequests++; return Respond(); }
        public NativeAmsiScanResponse ScanBuffer(byte[] content, string contentName)
        { BufferRequests++; LastBuffer = (byte[])content.Clone(); return Respond(); }
        private NativeAmsiScanResponse Respond()
        {
            if (_throwOnScan) throw new InvalidOperationException("Synthetic native request failure.");
            return _response;
        }
        public void Dispose() => IsDisposed = true;
    }
}
