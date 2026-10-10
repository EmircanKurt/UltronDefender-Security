using System;
using System.IO;
using System.Threading;
using AegisPC.Contracts.Caching;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Security.Kernel;
using KernelIpcService = AegisPC.Infrastructure.Kernel.KernelIpcService;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.DriverBridge;

/// <summary>Exposes connection lifecycle, not evidence that file access is actually blocked.</summary>
public interface IKernelBridge : IDisposable
{
    /// <summary>Indicates a connected native transport only; never a successful security intervention.</summary>
    bool IsDriverConnected { get; }
    /// <summary>Returns false while the identity-bound native pilot remains unverified.</summary>
    bool StartBridge();
    /// <summary>Disconnects transport resources without changing driver or operating-system policy.</summary>
    void StopBridge();
}

/// <summary>
/// Keeps the legacy path-only native transport disabled. Explicit read-only evaluations can collect
/// review signals, but cannot authorize blocking, quarantine, process protection or a success notification.
/// </summary>
public sealed class KernelBridge : IKernelBridge
{
    private readonly ILogger<KernelBridge>? _logger;
    private readonly IDetectionHub? _detectionHub;
    private readonly KernelIpcService _kernelIpc = new();
    private bool _isDisposed;

    /// <summary>The closed pilot does not connect to or activate a native driver.</summary>
    public bool IsDriverConnected => false;

    /// <summary>Reports that no identity-bound native enforcement has passed the pilot gates.</summary>
    public bool IsEnforcementActive => UltronFilterPilotPolicy.IdentityBoundEnforcementAvailable;

    /// <summary>
    /// Keeps existing injection signatures compatible. Legacy cache, findings, quarantine and audit
    /// services are intentionally not used: path-only observations are neither trusted cache entries nor action receipts.
    /// </summary>
    public KernelBridge(ILogger<KernelBridge>? logger = null, IDetectionHub? detectionHub = null,
        IScanCacheService? scanCacheService = null, ISecurityFindingService? findingService = null,
        IQuarantineService? quarantineService = null, IAuditLogService? auditLogService = null)
    {
        _logger = logger;
        _detectionHub = detectionHub;
    }

    /// <summary>Does not load or contact the legacy driver; identity-bound protocol and isolated VM validation are prerequisites.</summary>
    public bool StartBridge()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        _logger?.LogInformation("Ultron Filter legacy transport remains disabled: authenticated file identity, assigned altitude, signing and VM validation are pending. No pre-access blocking is active.");
        return false;
    }

    /// <summary>Releases any compatibility transport resources without starting or stopping a Windows driver.</summary>
    public void StopBridge() => _kernelIpc.Disconnect();

    /// <summary>
    /// Evaluates an existing file only as a review observation. Incoming write bytes are absent from the
    /// legacy request, so write requests are never interpreted as an authoritative scan of their future content.
    /// The return value is always false until native identity and receipt gates exist.
    /// </summary>
    public bool EvaluateKernelScanRequest(KernelIpcService.ScanRequest request)
    {
        if (_isDisposed || request.IsWriteOperation || request.ProcessId <= 4 ||
            request.ProcessId == (uint)Environment.ProcessId || string.IsNullOrWhiteSpace(request.FilePath))
            return false;
        try
        {
            if (_detectionHub == null || !File.Exists(request.FilePath)) return false;
            using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            var result = _detectionHub.EvaluateAsync(new DetectionContext
            {
                FilePath = request.FilePath,
                ProcessId = request.ProcessId <= int.MaxValue ? (int)request.ProcessId : null,
                IsRunningProcess = false,
                CorrelationId = Guid.NewGuid().ToString("N")
            }, timeout.Token).GetAwaiter().GetResult();
            if (result != null)
                _logger?.LogDebug("Legacy path observation reviewed for {Path}: verdict {Verdict}, score {Score}. No kernel action or applied receipt exists.",
                    request.FilePath, result.Verdict, result.RiskScore);
        }
        catch (OperationCanceledException)
        {
            _logger?.LogDebug("Legacy path observation exceeded its review budget for {Path}; access was not blocked.", request.FilePath);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Legacy path observation could not be inspected for {Path}; no action was taken.", request.FilePath);
        }
        return false;
    }

    /// <summary>Idempotently disposes read-only transport resources; no driver installation or native action occurs.</summary>
    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        _kernelIpc.Dispose();
    }
}
