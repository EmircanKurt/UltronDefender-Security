using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Kernel;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Kernel
{
    /// <summary>
    /// Reviews legacy path-only requests without authorizing native actions. A current file hash can
    /// support an observation but does not bind the kernel's pending stream or prove an applied block.
    /// </summary>
    public class KernelGatingEngine : IKernelGatingEngine
    {
        private const uint STATUS_SUCCESS = 0x00000000;
        private readonly IDetectionHub? _detectionHub;
        private readonly ILogger<KernelGatingEngine>? _logger;
        private int _timeoutFallbackCount;
        private DateTime _lastTimeoutAlert = DateTime.MinValue;

        /// <summary>
        /// Timeout nedeniyle fail-open izin verilen toplam dosya sayısı.
        /// </summary>
        public int TimeoutFallbackCount => _timeoutFallbackCount;

        /// <summary>Creates a read-only review engine; compatibility cache/signature/action dependencies cannot authorize native operations.</summary>
        public KernelGatingEngine(
            IDetectionHub? detectionHub = null,
            IScanCacheService? scanCache = null,
            ISignatureVerifier? signatureVerifier = null,
            IQuarantineService? quarantineService = null,
            ILogger<KernelGatingEngine>? logger = null)
        {
            _detectionHub = detectionHub;
            _logger = logger;
        }

        /// <summary>Creates the observation-only engine with optional diagnostic logging.</summary>
        public KernelGatingEngine(ILogger<KernelGatingEngine>? logger)
            : this(null, null, null, null, logger)
        {
        }

        /// <summary>Reports a bounded review result with no block/quarantine authority; legacy write inputs remain uninspected.</summary>
        public async Task<KernelGatingDecision> EvaluatePreOpDecisionAsync(KernelIpcMessage request, CancellationToken cancellationToken = default)
        {
            var sw = Stopwatch.StartNew();
            var decision = new KernelGatingDecision();

            if (request == null || string.IsNullOrWhiteSpace(request.FilePath))
            {
                decision.Status = KernelGatingStatus.Allowed;
                decision.NtStatus = STATUS_SUCCESS;
                decision.IsBlocked = false;
                decision.ShouldQuarantine = false;
                decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                return decision;
            }

            if (request.OpCode == MinifilterOperationType.PreWrite)
            {
                decision.Status = KernelGatingStatus.Allowed;
                decision.BlockReason = "Incoming write content is unavailable in this legacy protocol; no authoritative write inspection or action occurred.";
                decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                return decision;
            }

            try
            {
                // Timeout Güvencesi (Fail-Open): request.TimeoutMs (varsayılan 500ms) içinde yanıt verilemezse erişime izin ver
                uint timeoutMs = request.TimeoutMs > 0 ? request.TimeoutMs : 500;
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(timeoutMs));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                linkedCts.Token.ThrowIfCancellationRequested();

                // 1. Sistem Süreçleri ve Antivirüs PID Bypass
                if (request.ProcessId > 0 && (request.ProcessId <= 4 || request.ProcessId == Environment.ProcessId))
                {
                    decision.IsBlocked = false;
                    decision.NtStatus = STATUS_SUCCESS;
                    decision.Status = KernelGatingStatus.Allowed;
                    decision.BlockReason = "Sistem / Kendi sürecimiz bypass";
                    decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                    return decision;
                }

                // Paths, filenames, publishers and path/mtime caches do not establish a complete clean verdict.
                int riskScore = 0;
                string threatTitle = "No confirmed evidence";

                if (File.Exists(request.FilePath))
                {
                    var match = await MalwareSignatureDatabase.CheckFileContentPatternsAsync(request.FilePath, linkedCts.Token);
                    if (match.IsMatched)
                    {
                        riskScore = Math.Max(riskScore, match.SeverityScore);
                        threatTitle = match.ThreatName;
                    }
                }

                // Review all applicable detectors; signatures never suppress independent evidence.
                bool verifiedConfirmation = false;
                if (_detectionHub != null && File.Exists(request.FilePath))
                {
                    try
                    {
                        var ctx = new DetectionContext
                        {
                            FilePath = request.FilePath,
                            ProcessId = request.ProcessId > 0 ? request.ProcessId : null,
                            IsRunningProcess = false,
                            CorrelationId = Guid.NewGuid().ToString("N")
                        };

                        var hubResult = await _detectionHub.EvaluateAsync(ctx, linkedCts.Token);
                        if (hubResult != null)
                        {
                            verifiedConfirmation = await KernelEvidenceGate.HasCurrentAbsoluteSignatureAsync(
                                hubResult, request.FilePath, linkedCts.Token);
                            if (hubResult.RiskScore > riskScore)
                            {
                                riskScore = hubResult.RiskScore;
                                if (!string.IsNullOrWhiteSpace(hubResult.ThreatTitle))
                                {
                                    threatTitle = hubResult.ThreatTitle;
                                }
                            }
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "DetectionHub evaluation error for {Path}", request.FilePath);
                    }
                }

                // Even verified path content is an observation, not a native stream-bound action permit.
                decision.RiskScore = riskScore;

                if (verifiedConfirmation)
                {
                    decision.IsBlocked = false;
                    decision.NtStatus = STATUS_SUCCESS;
                    decision.Status = KernelGatingStatus.Allowed;
                    decision.ShouldQuarantine = false;
                    decision.BlockReason = $"Verified content signature observed: {threatTitle}. Identity-bound native enforcement and an applied receipt are unavailable; no block occurred.";
                }
                else if (riskScore >= 40)
                {
                    decision.IsBlocked = false;
                    decision.NtStatus = STATUS_SUCCESS;
                    decision.Status = KernelGatingStatus.Allowed;
                    decision.ShouldQuarantine = false;
                    decision.BlockReason = $"İzleme: doğrulanmamış dosya sinyali ({riskScore}) - {threatTitle}";
                }
                else
                {
                    decision.IsBlocked = false;
                    decision.NtStatus = STATUS_SUCCESS;
                    decision.Status = KernelGatingStatus.Allowed;
                    decision.ShouldQuarantine = false;
                    decision.BlockReason = "No verified block evidence; access allowed.";
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                decision.IsBlocked = false;
                decision.NtStatus = STATUS_SUCCESS;
                decision.Status = KernelGatingStatus.Allowed;
                decision.ShouldQuarantine = false;
                decision.BlockReason = "Review cancelled by the caller; no native action occurred.";
            }
            catch (OperationCanceledException)
            {
                // Fail-Open Güvenlik Garantisi: Zaman aşımı durumunda sistemi kilitlememek için izin ver
                decision.IsBlocked = false;
                decision.NtStatus = STATUS_SUCCESS;
                decision.Status = KernelGatingStatus.TimeoutFallbackAllowed;
                decision.ShouldQuarantine = false;
                decision.RiskScore = 0;
                decision.BlockReason = "Zaman aşımı nedeniyle fail-open izni verildi.";
                _logger?.LogWarning("Kernel gating timeout exceeded ({Timeout}ms) for {Path}. Fail-open granted.", request.TimeoutMs, request.FilePath);
                var count = Interlocked.Increment(ref _timeoutFallbackCount);
                // Kısa sürede çok sayıda timeout → potansiyel DoS/stres saldırısı uyarısı
                if (count > 50 && (DateTime.UtcNow - _lastTimeoutAlert).TotalMinutes >= 5)
                {
                    _lastTimeoutAlert = DateTime.UtcNow;
                    _logger?.LogWarning("Legacy review exceeded its budget {Count} times; this is a coverage/performance limitation, not attack evidence.", count);
                }
            }
            catch (Exception ex)
            {
                // Fail-Open Beklenmeyen Hata Koruması
                decision.IsBlocked = false;
                decision.NtStatus = STATUS_SUCCESS;
                decision.Status = KernelGatingStatus.Allowed;
                decision.ShouldQuarantine = false;
                decision.BlockReason = "Hata koruması: Fail-open izin verildi.";
                _logger?.LogTrace(ex, "Error evaluating kernel gating for {Path}", request.FilePath);
            }

            decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
            return decision;
        }
    }
}
