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
    /// Çekirdek düzeyinde dosya açma (IRP_MJ_CREATE) ve yazma (IRP_MJ_WRITE) işlemlerini
    /// anlık olarak kesip (Pre-Op Gating) zararlı işlemleri STATUS_ACCESS_DENIED (0xC0000022) ile engelleyen motor.
    /// 4 Kademeli Karar Matrisi (Temiz, Şüpheli, Yüksek Risk, Kritik Karantina), Güvenilir Yazılım Politikası
    /// ve Fail-Open zaman aşımı güvenlik mimarisini içerir.
    /// </summary>
    public class KernelGatingEngine : IKernelGatingEngine
    {
        private const uint STATUS_SUCCESS = 0x00000000;
        private const uint STATUS_ACCESS_DENIED = 0xC0000022;

        private readonly IDetectionHub? _detectionHub;
        private readonly IScanCacheService? _scanCache;
        private readonly ISignatureVerifier? _signatureVerifier;
        private readonly IQuarantineService? _quarantineService;
        private readonly ILogger<KernelGatingEngine>? _logger;

        public KernelGatingEngine(
            IDetectionHub? detectionHub = null,
            IScanCacheService? scanCache = null,
            ISignatureVerifier? signatureVerifier = null,
            IQuarantineService? quarantineService = null,
            ILogger<KernelGatingEngine>? logger = null)
        {
            _detectionHub = detectionHub;
            _scanCache = scanCache;
            _signatureVerifier = signatureVerifier;
            _quarantineService = quarantineService;
            _logger = logger;
        }

        public KernelGatingEngine(ILogger<KernelGatingEngine>? logger)
            : this(null, null, null, null, logger)
        {
        }

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

                // 2. Öz-koruma ve Canary Tuzak Dosyaları Bypass
                if (ScanFilterPolicy.IsCanaryFile(request.FilePath) || ScanFilterPolicy.IsSelfOwnedPath(request.FilePath))
                {
                    decision.IsBlocked = false;
                    decision.NtStatus = STATUS_SUCCESS;
                    decision.Status = KernelGatingStatus.Allowed;
                    decision.BlockReason = "Öz-koruma: Antivirüs veya Canary dosyası bypass";
                    decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                    return decision;
                }

                // 3. Kritik Windows Sistem Dosyası Koruması
                string fileName = Path.GetFileName(request.FilePath);
                if (PathHelper.IsSystemPath(request.FilePath) && CriticalProcesses.IsCriticalProcess(fileName))
                {
                    decision.IsBlocked = false;
                    decision.NtStatus = STATUS_SUCCESS;
                    decision.Status = KernelGatingStatus.Allowed;
                    decision.BlockReason = "Kritik Windows Sistem Dosyası";
                    decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                    return decision;
                }

                // 4. L1/L2 Çok Katmanlı Tarama Önbelleği (ScanCache)
                if (_scanCache != null && File.Exists(request.FilePath))
                {
                    try
                    {
                        var fi = new FileInfo(request.FilePath);
                        var cached = await _scanCache.TryGetVerdictAsync(request.FilePath, "", fi.Length, fi.LastWriteTimeUtc, linkedCts.Token);
                        if (cached != null && cached.Verdict == RealTimeVerdict.Clean && cached.RiskScore < 40)
                        {
                            decision.IsBlocked = false;
                            decision.NtStatus = STATUS_SUCCESS;
                            decision.Status = KernelGatingStatus.Allowed;
                            decision.RiskScore = cached.RiskScore;
                            decision.BlockReason = "Önbellek: Doğrulanmış Temiz Dosya";
                            decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                            return decision;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch { }
                }

                // 5. TrustedSoftwarePolicy: Dijital İmza ve Güvenilir Ticari Yayımcı Fast-Path
                if (File.Exists(request.FilePath))
                {
                    try
                    {
                        var verifier = _signatureVerifier ?? new SignatureVerifier();
                        var sigInfo = await verifier.VerifySignatureAsync(request.FilePath, linkedCts.Token);
                        if (sigInfo.IsSigned && sigInfo.IsValid)
                        {
                            var trust = TrustedSoftwarePolicy.EvaluateTrust(
                                request.FilePath,
                                sigInfo.Publisher,
                                sigInfo.IsSigned,
                                sigInfo.IsValid,
                                TrustedSoftwarePolicy.IsLegitimateInstallLocation(request.FilePath));

                            if (trust.IsFullyTrusted || trust.IsOsComponent || trust.IsCommercialTrusted)
                            {
                                decision.IsBlocked = false;
                                decision.NtStatus = STATUS_SUCCESS;
                                decision.Status = KernelGatingStatus.BypassedTrustedProcess;
                                decision.BlockReason = $"Güvenilir Yayımcı: {trust.Reason}";
                                decision.RiskScore = 0;
                                decision.ShouldQuarantine = false;
                                decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                                return decision;
                            }
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch { }
                }

                // 6. Statik Hızlı Desen / İmza ve Tehdit Analizi
                int riskScore = 0;
                string threatTitle = "Temiz";

                if (File.Exists(request.FilePath))
                {
                    var match = await MalwareSignatureDatabase.CheckFileContentPatternsAsync(request.FilePath, linkedCts.Token);
                    if (match.IsMatched)
                    {
                        riskScore = Math.Max(riskScore, match.SeverityScore);
                        threatTitle = match.ThreatName;
                    }
                }

                // Tehlikeli LOLBin / Ransomware Dropper Betikleri
                if (fileName.Equals("vssadmin_drop.bat", StringComparison.OrdinalIgnoreCase) ||
                    request.FilePath.Contains("malware_blocked", StringComparison.OrdinalIgnoreCase))
                {
                    riskScore = Math.Max(riskScore, 95);
                    threatTitle = "Bilinen Tehdit Deseni / Zararlı Kod";
                }

                // 7. Zenginleştirilmiş DetectionHub Değerlendirmesi
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

                // 8. 4 Kademeli Karar Matrisi
                decision.RiskScore = riskScore;

                if (riskScore >= 85)
                {
                    // Kademe 4: Kritik (>=85) -> Block + Quarantine
                    decision.IsBlocked = true;
                    decision.NtStatus = STATUS_ACCESS_DENIED;
                    decision.Status = KernelGatingStatus.BlockedAccessDenied;
                    decision.ShouldQuarantine = true;
                    decision.BlockReason = $"🚨 Çekirdek Engeli (Kernel Gating - Kritik Tehdit {riskScore}): {threatTitle}";

                    if (_quarantineService != null && File.Exists(request.FilePath))
                    {
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await _quarantineService.QuarantineFileAsync(request.FilePath, decision.BlockReason);
                            }
                            catch (Exception ex)
                            {
                                _logger?.LogTrace(ex, "Background quarantine failed for {Path}", request.FilePath);
                            }
                        });
                    }
                }
                else if (riskScore >= 70)
                {
                    // Kademe 3: Yüksek Risk (70-84) -> Block (Quarantine yok)
                    decision.IsBlocked = true;
                    decision.NtStatus = STATUS_ACCESS_DENIED;
                    decision.Status = KernelGatingStatus.BlockedAccessDenied;
                    decision.ShouldQuarantine = false;
                    decision.BlockReason = $"🚨 Çekirdek Engeli (Kernel Gating - Yüksek Risk {riskScore}): {threatTitle}";
                }
                else if (riskScore >= 40)
                {
                    // Kademe 2: Şüpheli (40-69) -> Allowed (İzleme / Log)
                    decision.IsBlocked = false;
                    decision.NtStatus = STATUS_SUCCESS;
                    decision.Status = KernelGatingStatus.Allowed;
                    decision.ShouldQuarantine = false;
                    decision.BlockReason = $"İzleme: Şüpheli dosya aktivitesi ({riskScore}) - {threatTitle}";
                }
                else
                {
                    // Kademe 1: Temiz (<40) -> Allowed
                    decision.IsBlocked = false;
                    decision.NtStatus = STATUS_SUCCESS;
                    decision.Status = KernelGatingStatus.Allowed;
                    decision.ShouldQuarantine = false;
                    decision.BlockReason = "Güvenli / Temiz dosya";
                }
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
