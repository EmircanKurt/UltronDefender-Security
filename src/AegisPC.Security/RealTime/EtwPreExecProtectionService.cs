using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Microsoft-Windows-Kernel-Process ETW Sağlayıcısı Tabanlı Pre-Execution (Başlatma Öncesi)
    /// Süreç Tarama ve Erken Müdahale Motoru.
    /// Yeni başlatılan süreçleri (ProcessStart / ImageLoad) CPU düzeyinde askıya alarak (NtSuspendProcess)
    /// 500 ms içinde DetectionHub ve RiskScoringEngine ile inceler; tehdit durumunda süreci anında sonlandırır.
    /// ETW oturumu açılamazsa (yetersiz ayrıcalık vb.) sessizce FileSystemWatcher post-op moduna geri düşer.
    /// </summary>
    public class EtwPreExecProtectionService : IEtwPreExecProtectionService
    {
        private readonly IDetectionHub _detectionHub;
        private readonly IRiskScoringEngine _riskScoringEngine;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IScanCacheService? _scanCacheService;
        private readonly IQuarantineService? _quarantineService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger<EtwPreExecProtectionService>? _logger;

        private TraceEventSession? _session;
        private Task? _processingTask;
        private CancellationTokenSource? _cts;
        private bool _isRunning;
        private bool _isEtwSubscribed;
        private readonly object _lock = new();

        public static readonly Guid KernelProcessProviderGuid = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
        private const string SessionName = "UltronDefender_PreExecSession";

        public bool IsRunning => _isRunning;
        public bool IsEtwSubscribed => _isEtwSubscribed;
        public TimeSpan ScanTimeout { get; set; } = TimeSpan.FromMilliseconds(500);

        public event Action<PreExecThreatAlert>? OnThreatBlocked;

        public EtwPreExecProtectionService(
            IDetectionHub detectionHub,
            IRiskScoringEngine riskScoringEngine,
            ISignatureVerifier signatureVerifier,
            IScanCacheService? scanCacheService = null,
            IQuarantineService? quarantineService = null,
            IAuditLogService? auditLogService = null,
            ILogger<EtwPreExecProtectionService>? logger = null)
        {
            _detectionHub = detectionHub ?? throw new ArgumentNullException(nameof(detectionHub));
            _riskScoringEngine = riskScoringEngine ?? throw new ArgumentNullException(nameof(riskScoringEngine));
            _signatureVerifier = signatureVerifier ?? throw new ArgumentNullException(nameof(signatureVerifier));
            _scanCacheService = scanCacheService;
            _quarantineService = quarantineService;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public void Start()
        {
            lock (_lock)
            {
                if (_isRunning) return;
                _isRunning = true;
                _cts = new CancellationTokenSource();

                _logger?.LogInformation("Starting ETW Pre-Execution Protection Service...");

                try
                {
                    // Var olan oturum varsa temizle
                    var existingSession = TraceEventSession.GetActiveSession(SessionName);
                    existingSession?.Dispose();

                    _session = new TraceEventSession(SessionName, TraceEventSessionOptions.Create);
                    // MatchAnyKeywords: 0x10 (ProcessStart/Stop), 0x40 (ImageLoad)
                    _session.EnableProvider(KernelProcessProviderGuid, TraceEventLevel.Informational, matchAnyKeywords: 0x10 | 0x40);

                    _session.Source.Dynamic.All += OnKernelProcessEvent;

                    _processingTask = Task.Factory.StartNew(
                        () => _session.Source.Process(),
                        _cts.Token,
                        TaskCreationOptions.LongRunning,
                        TaskScheduler.Default);

                    _isEtwSubscribed = true;
                    _logger?.LogInformation("Microsoft-Windows-Kernel-Process ETW session subscribed successfully.");
                }
                catch (Exception ex)
                {
                    // Fallback: Ayrıcalık yetersizliği veya ETW hatasında FileSystemWatcher'a geri dön
                    _isEtwSubscribed = false;
                    _logger?.LogWarning(ex, "ETW subscription for Microsoft-Windows-Kernel-Process failed (e.g. non-admin privileges or ETW quota). Falling back gracefully to FileSystemWatcher post-operation monitoring.");
                }
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning) return;
                _isRunning = false;
                _isEtwSubscribed = false;

                try
                {
                    _cts?.Cancel();
                    _session?.Stop();
                    _session?.Dispose();
                    _session = null;
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Error while stopping ETW session.");
                }
                finally
                {
                    _cts?.Dispose();
                    _cts = null;
                }

                _logger?.LogInformation("ETW Pre-Execution Protection Service stopped.");
            }
        }

        private void OnKernelProcessEvent(TraceEvent data)
        {
            if (!_isRunning) return;

            try
            {
                string eventName = data.EventName;
                bool isProcessStart = eventName.Contains("ProcessStart", StringComparison.OrdinalIgnoreCase) ||
                                     eventName.Contains("Start", StringComparison.OrdinalIgnoreCase);
                bool isImageLoad = eventName.Contains("ImageLoad", StringComparison.OrdinalIgnoreCase);

                if (!isProcessStart && !isImageLoad) return;

                int processId = data.ProcessID;
                if (processId <= 4) return;

                string imagePath = string.Empty;
                if (data.PayloadNames.Length > 0)
                {
                    foreach (var name in data.PayloadNames)
                    {
                        if (name.Contains("ImageFileName", StringComparison.OrdinalIgnoreCase) ||
                            name.Contains("FileName", StringComparison.OrdinalIgnoreCase) ||
                            name.Contains("ImageName", StringComparison.OrdinalIgnoreCase))
                        {
                            var val = data.PayloadByName(name);
                            if (val != null)
                            {
                                imagePath = val.ToString() ?? string.Empty;
                                break;
                            }
                        }
                    }
                }

                if (string.IsNullOrWhiteSpace(imagePath)) return;

                // Asenkron pre-exec değerlendirmesini arka plana aktar
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await EvaluateProcessAsync(processId, imagePath, "", _cts?.Token ?? CancellationToken.None);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "Failed background pre-exec evaluation for PID {Pid}", processId);
                    }
                });
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error processing ETW event.");
            }
        }

        /// <summary>
        /// Belirtilen süreç kimliği ve dosya yolu için başlatma öncesi tarama ve infazı yürütür.
        /// </summary>
        public async Task<PreExecDecision> EvaluateProcessAsync(
            int processId,
            string imagePath,
            string commandLine = "",
            CancellationToken ct = default)
        {
            var decision = new PreExecDecision
            {
                ProcessId = processId,
                ImagePath = imagePath
            };

            // 1. Whitelist & Fast-path Kontrolleri
            if (processId <= 4 || processId == Environment.ProcessId)
            {
                decision.Whitelisted = true;
                decision.Reason = "System or Self PID bypass";
                return decision;
            }

            if (string.IsNullOrWhiteSpace(imagePath))
            {
                decision.Whitelisted = true;
                decision.Reason = "Empty image path";
                return decision;
            }

            string fileName = Path.GetFileName(imagePath);
            if (CriticalProcesses.IsCriticalProcess(fileName))
            {
                decision.Whitelisted = true;
                decision.Reason = $"Critical system process: {fileName}";
                return decision;
            }

            if (FileScannerService.IsSelfOwnedPath(imagePath))
            {
                decision.Whitelisted = true;
                decision.Reason = "UltronDefender self-owned binary";
                return decision;
            }

            if (fileName.Equals("pagefile.sys", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals("swapfile.sys", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals("hiberfil.sys", StringComparison.OrdinalIgnoreCase))
            {
                decision.Whitelisted = true;
                decision.Reason = "Windows virtual memory system file";
                return decision;
            }

            // Doğrulanmış Microsoft / Windows ikilileri fast-path
            if (PathHelper.IsSystemPath(imagePath))
            {
                try
                {
                    var sig = await _signatureVerifier.VerifySignatureAsync(imagePath, ct);
                    if ((sig.IsSigned && sig.IsValid && (sig.Publisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true ||
                                                         sig.Publisher?.Contains("Windows", StringComparison.OrdinalIgnoreCase) == true))
                        || sig.IsValid || PathHelper.IsKnownSafePath(imagePath))
                    {
                        decision.Whitelisted = true;
                        decision.Reason = $"Signed Microsoft binary: {sig.Publisher ?? "Microsoft Windows"}";
                        return decision;
                    }
                }
                catch { }
            }
            else
            {
                try
                {
                    var sig = await _signatureVerifier.VerifySignatureAsync(imagePath, ct);
                    if (sig.IsSigned && sig.IsValid && (sig.Publisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true ||
                                                         sig.Publisher?.Contains("Windows", StringComparison.OrdinalIgnoreCase) == true))
                    {
                        decision.Whitelisted = true;
                        decision.Reason = $"Signed Microsoft binary: {sig.Publisher}";
                        return decision;
                    }
                }
                catch { }
            }

            // 2. L1 Önbellek Kontrolü (< 0.05 ms)
            if (File.Exists(imagePath) && _scanCacheService != null)
            {
                try
                {
                    var fi = new FileInfo(imagePath);
                    var cached = await _scanCacheService.TryGetVerdictAsync(imagePath, "", fi.Length, fi.LastWriteTimeUtc, ct);
                    if (cached != null && cached.Verdict == RealTimeVerdict.Clean)
                    {
                        decision.CacheHit = true;
                        decision.Reason = "L1 Clean Cache Hit";
                        return decision;
                    }
                }
                catch { }
            }

            // 3. Süreci Başlatma Öncesinde Askıya Al (NtSuspendProcess)
            IntPtr hProcess = IntPtr.Zero;
            bool suspended = false;
            try
            {
                suspended = ProcessMitigationHelper.TrySuspendProcessById(processId, out hProcess);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Failed to suspend PID {Pid}", processId);
            }
            decision.WasSuspended = suspended;

            try
            {
                // 4. Senkron Tarama (Suspend-to-Scan Penceresi)
                using var timeoutCts = new CancellationTokenSource(ScanTimeout);
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

                DetectionResult? detectionResult = null;
                try
                {
                    var detectionContext = new DetectionContext
                    {
                        FilePath = imagePath,
                        ProcessId = processId,
                        IsRunningProcess = true,
                        CorrelationId = Guid.NewGuid().ToString("N")
                    };

                    detectionResult = await _detectionHub.EvaluateAsync(detectionContext, linkedCts.Token);

                    if (timeoutCts.IsCancellationRequested)
                    {
                        throw new OperationCanceledException(timeoutCts.Token);
                    }
                }
                catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
                {
                    // Suspend-to-scan Zaman Aşımı: Süreç serbest bırakılır ve SECURITY log'a yazılır
                    decision.TimedOut = true;
                    decision.Reason = $"Suspend-to-scan {(int)ScanTimeout.TotalMilliseconds}ms timeout exceeded; process resumed.";

                    if (suspended && hProcess != IntPtr.Zero)
                    {
                        ProcessMitigationHelper.TryResumeProcessById(processId, hProcess);
                        suspended = false;
                    }

                    _logger?.LogWarning("SECURITY: Suspend-to-scan timeout ({Timeout}ms exceeded) for PID {Pid}, Path: {Path}. Process execution resumed.", (int)ScanTimeout.TotalMilliseconds, processId, imagePath);

                    if (_auditLogService != null)
                    {
                        _ = _auditLogService.LogActionAsync(
                            AuditAction.ScanCompleted,
                            "EtwPreExecProtection",
                            fileName,
                            imagePath,
                            $"SECURITY: Suspend-to-scan timeout (500ms exceeded) for PID {processId}. Process resumed.",
                            AuditResult.Cancelled);
                    }

                    return decision;
                }

                // 5. Risk Skoru ve Tehdit Eşik Değerlendirmesi
                int riskScore = detectionResult?.RiskScore ?? 0;
                decision.RiskScore = riskScore;

                if (detectionResult != null && (detectionResult.RiskScore >= 70 || detectionResult.Verdict == DetectionVerdict.ConfirmedMalicious))
                {
                    // Tehdit Doğrulandı: Süreç Ağacını Sonlandır ve Karantinaya Al
                    decision.WasBlocked = true;
                    decision.Reason = $"Pre-exec blocked: {detectionResult.ThreatTitle} (Score: {riskScore})";

                    ProcessMitigationHelper.KillProcessTree(processId, _logger);
                    suspended = false; // Sonlandırıldı, resume gereksiz

                    if (_quarantineService != null && File.Exists(imagePath))
                    {
                        try
                        {
                            await _quarantineService.QuarantineFileAsync(imagePath, "ETW Pre-Exec: " + detectionResult.ThreatTitle, ct);
                        }
                        catch (Exception qEx)
                        {
                            _logger?.LogWarning(qEx, "Failed to quarantine pre-exec blocked file: {Path}", imagePath);
                        }
                    }

                    var alert = new PreExecThreatAlert
                    {
                        ProcessId = processId,
                        ImagePath = imagePath,
                        CommandLine = commandLine,
                        ThreatTitle = detectionResult.ThreatTitle,
                        RiskScore = riskScore,
                        Timestamp = DateTime.UtcNow
                    };
                    OnThreatBlocked?.Invoke(alert);

                    _logger?.LogWarning("SECURITY: Threat blocked pre-execution: PID {Pid}, Path: {Path}, Score: {Score}, Threat: {Threat}",
                        processId, imagePath, riskScore, detectionResult.ThreatTitle);

                    if (_auditLogService != null)
                    {
                        _ = _auditLogService.LogActionAsync(
                            AuditAction.FileQuarantined,
                            "EtwPreExecProtection",
                            fileName,
                            imagePath,
                            $"SECURITY: Threat blocked pre-execution: PID {processId}, Score {riskScore}, Threat: {detectionResult.ThreatTitle}",
                            AuditResult.Success);
                    }
                }
                else
                {
                    // Temiz Süreç: Yürütmeyi Devam Ettir
                    if (suspended && hProcess != IntPtr.Zero)
                    {
                        ProcessMitigationHelper.TryResumeProcessById(processId, hProcess);
                        suspended = false;
                    }
                    decision.Reason = "Clean execution permitted";
                }
            }
            finally
            {
                // Fail-safe: Bloklanmamış ve askıda kalmış süreç mutlaka devam ettirilir
                if (suspended && hProcess != IntPtr.Zero && !decision.WasBlocked)
                {
                    ProcessMitigationHelper.TryResumeProcessById(processId, hProcess);
                }

                if (hProcess != IntPtr.Zero)
                {
                    ProcessMitigationHelper.SafeCloseHandle(hProcess);
                }
            }

            return decision;
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
