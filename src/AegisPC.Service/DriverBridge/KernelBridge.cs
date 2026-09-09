using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Infrastructure.Kernel;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.DriverBridge
{
    public interface IKernelBridge : IDisposable
    {
        bool IsDriverConnected { get; }
        bool StartBridge();
        void StopBridge();
    }

    /// <summary>
    /// Ring-0 Kernel Minifilter (AegisFilter.sys) ile Ring-3 Windows Servisi arasindaki
    /// guvenli iletisim koprusu. Gelen I/O isteklerini IDetectionHub ve ScanCache ile
    /// mikrosaniye seviyesinde degerlendirir ve bloklama/izin karari uretir.
    /// </summary>
    public class KernelBridge : IKernelBridge
    {
        private readonly ILogger<KernelBridge>? _logger;
        private readonly IDetectionHub? _detectionHub;
        private readonly IScanCacheService? _scanCacheService;
        private readonly KernelIpcService _kernelIpc;
        private bool _isDriverConnected;
        private bool _isDisposed;

        public bool IsDriverConnected => _isDriverConnected;

        public KernelBridge(
            ILogger<KernelBridge>? logger = null,
            IDetectionHub? detectionHub = null,
            IScanCacheService? scanCacheService = null)
        {
            _logger = logger;
            _detectionHub = detectionHub;
            _scanCacheService = scanCacheService;
            _kernelIpc = new KernelIpcService();
        }

        public bool StartBridge()
        {
            if (_isDriverConnected) return true;

            try
            {
                _logger?.LogInformation("Attempting to connect to AegisFilter kernel minifilter...");
                _isDriverConnected = _kernelIpc.ConnectToDriver();

                if (_isDriverConnected)
                {
                    _logger?.LogInformation("Connected successfully to AegisFilter communication port (\\AegisFilterPort). Starting listener...");
                    _kernelIpc.StartListener(EvaluateKernelScanRequest);
                    return true;
                }
                else
                {
                    _logger?.LogInformation("AegisFilter kernel driver not active or not loaded. System operating in User-Mode Progressive Protection fallback.");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to initialize kernel bridge connection. Continuing with user-mode telemetry.");
                _isDriverConnected = false;
                return false;
            }
        }

        public void StopBridge()
        {
            _isDriverConnected = false;
            _kernelIpc.Dispose();
            _logger?.LogInformation("Kernel bridge stopped.");
        }

        /// <summary>
        /// Cekirdekten gelen IRP_MJ_CREATE / Write isteklerini degerlendirir.
        /// true: BlockAccess (STATUS_ACCESS_DENIED)
        /// false: AllowAccess
        /// </summary>
        public bool EvaluateKernelScanRequest(KernelIpcService.ScanRequest request)
        {
            try
            {
                string filePath = request.FilePath;
                uint pid = request.ProcessId;

                // 1. Hizli Whitelist & Bypass Kontrolleri
                if (pid <= 4 || pid == (uint)Environment.ProcessId)
                {
                    return false; // Sistem / Kendi surecimiz bypass
                }

                if (string.IsNullOrWhiteSpace(filePath))
                {
                    return false;
                }

                string fileName = Path.GetFileName(filePath);
                if (CriticalProcesses.IsCriticalProcess(fileName) ||
                    PathHelper.IsSystemPath(filePath) ||
                    AegisPC.Security.Scanning.ScanFilterPolicy.IsSelfOwnedPath(filePath))
                {
                    return false;
                }

                // 2. L1/L2 Onbellek Kontrolu
                if (_scanCacheService != null && File.Exists(filePath))
                {
                    try
                    {
                        var fi = new FileInfo(filePath);
                        var cached = _scanCacheService.TryGetVerdictAsync(filePath, "", fi.Length, fi.LastWriteTimeUtc).GetAwaiter().GetResult();
                        if (cached != null && cached.Verdict == RealTimeVerdict.Clean)
                        {
                            return false;
                        }
                    }
                    catch { }
                }

                // 3. Tespit Motoruyla Degerlendirme
                if (_detectionHub != null && File.Exists(filePath))
                {
                    var ctx = new DetectionContext
                    {
                        FilePath = filePath,
                        ProcessId = (int)pid,
                        IsRunningProcess = false,
                        CorrelationId = Guid.NewGuid().ToString("N")
                    };

                    using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
                    var detectionResult = _detectionHub.EvaluateAsync(ctx, cts.Token).GetAwaiter().GetResult();

                    if (detectionResult != null && (detectionResult.RiskScore >= 70 || detectionResult.Verdict == DetectionVerdict.ConfirmedMalicious))
                    {
                        _logger?.LogWarning("KERNEL INTERCEPTION: Blocked malicious file I/O '{Path}' from PID {Pid} (Threat: {Threat}, Score: {Score})",
                            filePath, pid, detectionResult.ThreatTitle, detectionResult.RiskScore);
                        return true; // BLOCK ACCESS
                    }
                }

                return false; // ALLOW ACCESS
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error evaluating kernel scan request for '{Path}'", request.FilePath);
                return false; // Fail-open (sistem kilitlenmesini onlemek icin)
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
            StopBridge();
        }
    }
}
