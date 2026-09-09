using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
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
        private readonly ISecurityFindingService? _findingService;
        private readonly IQuarantineService? _quarantineService;
        private readonly IAuditLogService? _auditLogService;
        private readonly KernelIpcService _kernelIpc;
        private bool _isDriverConnected;
        private bool _isDisposed;

        public bool IsDriverConnected => _isDriverConnected;

        public KernelBridge(
            ILogger<KernelBridge>? logger = null,
            IDetectionHub? detectionHub = null,
            IScanCacheService? scanCacheService = null,
            ISecurityFindingService? findingService = null,
            IQuarantineService? quarantineService = null,
            IAuditLogService? auditLogService = null)
        {
            _logger = logger;
            _detectionHub = detectionHub;
            _scanCacheService = scanCacheService;
            _findingService = findingService;
            _quarantineService = quarantineService;
            _auditLogService = auditLogService;
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
                    uint currentPid = (uint)Environment.ProcessId;
                    bool registered = _kernelIpc.RegisterProtectedProcess(currentPid);
                    _logger?.LogInformation("Connected successfully to AegisFilter communication port (\\AegisFilterPort). Protected PID {Pid} registered for Ring-0 Anti-Tamper (Success: {Registered}). Starting listener worker pool...", currentPid, registered);
                    _kernelIpc.StartListener(EvaluateKernelScanRequest, workerThreads: 4);
                    return true;
                }
                else
                {
                    _logger?.LogInformation("AegisFilter kernel driver (.sys) is NOT active or not loaded on port \\AegisFilterPort. System operating in Truthful User-Mode Progressive Protection fallback (ETW Pre-Exec + FileSystemWatcher). Gating status: DEGRADED (USER-MODE ONLY).");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to initialize kernel bridge connection. Continuing with truthful user-mode telemetry.");
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

                    if (detectionResult != null)
                    {
                        int score = detectionResult.RiskScore;
                        var evidenceReasons = detectionResult.Evidences != null && detectionResult.Evidences.Count > 0
                            ? detectionResult.Evidences.Select(e => e.Description).ToList()
                            : new List<string> { detectionResult.ThreatTitle };

                        // 3a. CRITICAL THREAT: Risk >= 85 veya ConfirmedMalicious -> QUARANTINE + BLOCK
                        if (score >= 85 || detectionResult.Verdict == DetectionVerdict.ConfirmedMalicious)
                        {
                            _logger?.LogCritical("🚨 KERNEL PRE-OP INTERCEPTION [QUARANTINE]: Intercepted critical malicious payload '{Path}' from PID {Pid} (Threat: {Threat}, Score: {Score})",
                                filePath, pid, detectionResult.ThreatTitle, score);

                            var finding = new SecurityFinding
                            {
                                ObjectPath = filePath,
                                ObjectName = fileName,
                                SHA256 = detectionResult.SHA256,
                                RiskScore = score,
                                RiskLevel = RiskLevel.ConfirmedMalicious,
                                Category = FindingCategory.MalwareSuspicion,
                                Title = string.IsNullOrWhiteSpace(detectionResult.ThreatTitle) ? "Ring-0 Intercepted Malware" : detectionResult.ThreatTitle,
                                Description = $"Ring-0 Minifilter intercepted confirmed malicious file I/O from PID {pid}. Access blocked (STATUS_ACCESS_DENIED) and staged for quarantine.",
                                ConfidenceLevel = ConfidenceLevel.High,
                                Status = FindingStatus.Active,
                                RiskReasons = evidenceReasons
                            };

                            _ = Task.Run(async () =>
                            {
                                try
                                {
                                    if (_quarantineService != null && File.Exists(filePath))
                                    {
                                        bool quarantined = await _quarantineService.QuarantineFileAsync(filePath, detectionResult.ThreatTitle ?? "Kernel Intercepted Malware");
                                        if (quarantined) finding.Status = FindingStatus.Resolved;
                                    }
                                    if (_findingService != null)
                                    {
                                        await _findingService.AddFindingAsync(finding);
                                    }
                                    if (_auditLogService != null)
                                    {
                                        await _auditLogService.LogActionAsync(
                                            AuditAction.FileQuarantined,
                                            "KernelMinifilter",
                                            fileName,
                                            filePath,
                                            $"Critical malware blocked and quarantined from PID {pid}. Threat: {detectionResult.ThreatTitle}, Score: {score}",
                                            AuditResult.Success);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger?.LogTrace(ex, "Background quarantine execution failed for '{Path}'", filePath);
                                }
                            });

                            return true; // BLOCK ACCESS (STATUS_ACCESS_DENIED)
                        }
                        // 3b. HIGH RISK: Risk 70-84 -> BLOCK
                        else if (score >= 70)
                        {
                            _logger?.LogWarning("🛡️ KERNEL PRE-OP INTERCEPTION [BLOCK]: Blocked high-risk file access '{Path}' from PID {Pid} (Threat: {Threat}, Score: {Score})",
                                filePath, pid, detectionResult.ThreatTitle, score);

                            var finding = new SecurityFinding
                            {
                                ObjectPath = filePath,
                                ObjectName = fileName,
                                SHA256 = detectionResult.SHA256,
                                RiskScore = score,
                                RiskLevel = RiskLevel.HighRisk,
                                Category = FindingCategory.MalwareSuspicion,
                                Title = string.IsNullOrWhiteSpace(detectionResult.ThreatTitle) ? "Kernel Blocked I/O" : detectionResult.ThreatTitle,
                                Description = $"Kernel minifilter blocked file access from PID {pid}. Gating enforced (STATUS_ACCESS_DENIED).",
                                ConfidenceLevel = ConfidenceLevel.High,
                                Status = FindingStatus.Active,
                                RiskReasons = evidenceReasons
                            };

                            _ = Task.Run(async () =>
                            {
                                try
                                {
                                    if (_findingService != null)
                                    {
                                        await _findingService.AddFindingAsync(finding);
                                    }
                                    if (_auditLogService != null)
                                    {
                                        await _auditLogService.LogActionAsync(
                                            AuditAction.FileBlocked,
                                            "KernelMinifilter",
                                            fileName,
                                            filePath,
                                            $"High-risk file access blocked from PID {pid}. Threat: {detectionResult.ThreatTitle}, Score: {score}",
                                            AuditResult.Success);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger?.LogTrace(ex, "Background audit/finding logging failed for '{Path}'", filePath);
                                }
                            });

                            return true; // BLOCK ACCESS (STATUS_ACCESS_DENIED)
                        }
                        // 3c. MEDIUM RISK / SUSPICIOUS: Risk 40-69 -> ALLOW (MONITOR + TELEMETRY)
                        else if (score >= 40)
                        {
                            _logger?.LogInformation("⚠️ KERNEL TELEMETRY [SUSPICIOUS]: Monitored suspicious I/O '{Path}' from PID {Pid} (Threat: {Threat}, Score: {Score})",
                                filePath, pid, detectionResult.ThreatTitle, score);

                            var finding = new SecurityFinding
                            {
                                ObjectPath = filePath,
                                ObjectName = fileName,
                                SHA256 = detectionResult.SHA256,
                                RiskScore = score,
                                RiskLevel = RiskLevel.Suspicious,
                                Category = FindingCategory.MalwareSuspicion,
                                Title = string.IsNullOrWhiteSpace(detectionResult.ThreatTitle) ? "Suspicious I/O Activity" : detectionResult.ThreatTitle,
                                Description = $"Kernel telemetry monitored suspicious file I/O from PID {pid}. (Risk Score: {score})",
                                ConfidenceLevel = ConfidenceLevel.Medium,
                                Status = FindingStatus.Active,
                                RiskReasons = evidenceReasons
                            };

                            _ = Task.Run(async () =>
                            {
                                try
                                {
                                    if (_findingService != null)
                                    {
                                        await _findingService.AddFindingAsync(finding);
                                    }
                                    if (_auditLogService != null)
                                    {
                                        await _auditLogService.LogActionAsync(
                                            AuditAction.ScanCompleted,
                                            "KernelTelemetry",
                                            fileName,
                                            filePath,
                                            $"Suspicious file I/O monitored from PID {pid}. Threat: {detectionResult.ThreatTitle}, Score: {score}",
                                            AuditResult.Success);
                                    }
                                }
                                catch { }
                            });

                            return false; // ALLOW ACCESS (TELEMETRY ONLY)
                        }
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
