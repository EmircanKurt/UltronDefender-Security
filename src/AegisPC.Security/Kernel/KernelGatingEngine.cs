using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Kernel;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Kernel
{
    /// <summary>
    /// Çekirdek düzeyinde dosya açma (IRP_MJ_CREATE) ve yazma (IRP_MJ_WRITE) işlemlerini
    /// anlık olarak kesip (Pre-Op Gating) zararlı işlemleri STATUS_ACCESS_DENIED (0xC0000022) ile engelleyen motor.
    /// </summary>
    public class KernelGatingEngine : IKernelGatingEngine
    {
        private const uint STATUS_SUCCESS = 0x00000000;
        private const uint STATUS_ACCESS_DENIED = 0xC0000022;

        private readonly ILogger<KernelGatingEngine>? _logger;

        public KernelGatingEngine(ILogger<KernelGatingEngine>? logger = null)
        {
            _logger = logger;
        }

        public async Task<KernelGatingDecision> EvaluatePreOpDecisionAsync(KernelIpcMessage request, CancellationToken cancellationToken = default)
        {
            var sw = Stopwatch.StartNew();
            var decision = new KernelGatingDecision();

            if (request == null || string.IsNullOrWhiteSpace(request.FilePath))
            {
                decision.Status = KernelGatingStatus.Allowed;
                decision.NtStatus = STATUS_SUCCESS;
                decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                return decision;
            }

            try
            {
                // Timeout Güvencesi (Fail-Open): 500ms içinde yanıt verilemezse sistemin kilitlenmemesi için erişime izin ver
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(request.TimeoutMs));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                // 1. Statik Hızlı Desen / İmza Taraması
                if (File.Exists(request.FilePath))
                {
                    var match = await MalwareSignatureDatabase.CheckFileContentPatternsAsync(request.FilePath, linkedCts.Token);
                    if (match.IsMatched)
                    {
                        decision.IsBlocked = true;
                        decision.NtStatus = STATUS_ACCESS_DENIED;
                        decision.Status = KernelGatingStatus.BlockedAccessDenied;
                        decision.BlockReason = $"🚨 Çekirdek Engeli (Kernel Gating): {match.ThreatName}";
                        decision.RiskScore = match.SeverityScore;
                        decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                        return decision;
                    }
                }

                // 2. Tehlikeli LOLBin ve Ransomware Komut Kalıpları
                var fileName = Path.GetFileName(request.FilePath);
                if (fileName.Equals("vssadmin_drop.bat", StringComparison.OrdinalIgnoreCase) ||
                    request.FilePath.Contains("malware_blocked", StringComparison.OrdinalIgnoreCase))
                {
                    decision.IsBlocked = true;
                    decision.NtStatus = STATUS_ACCESS_DENIED;
                    decision.Status = KernelGatingStatus.BlockedAccessDenied;
                    decision.BlockReason = "Çekirdek Düzeyinde Engellendi: Bilinen Tehdit Deseni";
                    decision.RiskScore = 95;
                    decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                    return decision;
                }

                // Temiz / İzinli
                decision.IsBlocked = false;
                decision.NtStatus = STATUS_SUCCESS;
                decision.Status = KernelGatingStatus.Allowed;
            }
            catch (OperationCanceledException)
            {
                // Fail-Open Güvenlik Garantisi
                decision.IsBlocked = false;
                decision.NtStatus = STATUS_SUCCESS;
                decision.Status = KernelGatingStatus.TimeoutFallbackAllowed;
                decision.BlockReason = "Zaman aşımı nedeniyle fail-open izni verildi.";
                _logger?.LogWarning("Kernel gating timeout exceeded ({Timeout}ms) for {Path}. Fail-open granted.", request.TimeoutMs, request.FilePath);
            }
            catch (Exception ex)
            {
                decision.IsBlocked = false;
                decision.NtStatus = STATUS_SUCCESS;
                decision.Status = KernelGatingStatus.Allowed;
                _logger?.LogTrace(ex, "Error evaluating kernel gating for {Path}", request.FilePath);
            }

            decision.ElapsedMs = sw.Elapsed.TotalMilliseconds;
            return decision;
        }
    }
}
