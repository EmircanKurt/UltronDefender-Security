using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Fidye virüsü eylemlerini durduran, süreci sonlandıran ve karantina uygulayan infazcı arayüzü.
    /// </summary>
    public interface IRansomwareEnforcementHandler
    {
        /// <summary>
        /// Toplam engellenen fidye saldırısı sayısı.
        /// </summary>
        int TotalBlockedAttempts { get; }

        /// <summary>
        /// Fidye saldırısı tespit edildiğinde tetiklenen olay.
        /// </summary>
        event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected;

        /// <summary>
        /// Kullanıcı arayüzüne bildirim (Toast) gönderildiğinde tetiklenen olay.
        /// </summary>
        event Action<string, string, string>? OnNotificationRaised;

        /// <summary>
        /// Tehdidi değerlendirir, saldırgan süreci tespit edip sonlandırır ve dosyayı karantinaya alır.
        /// </summary>
        Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(
            string offendingPath,
            string reason,
            int riskScore,
            int pid = 0,
            Func<string, bool>? isAppAllowed = null);
    }

    /// <summary>
    /// Fidye yazılımı tehditlerini değerlendiren, hedef süreci derhal öldüren (Kill)
    /// ve zararlı ikiliyi AES-256 kasaya kilitleyen infaz sınıfı.
    /// </summary>
    public class RansomwareEnforcementHandler : IRansomwareEnforcementHandler
    {
        private readonly IQuarantineService? _quarantineService;
        private readonly ISecurityFindingService? _findingService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger? _logger;

        private int _totalBlockedCount;

        public int TotalBlockedAttempts => _totalBlockedCount;

        public event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected;
        public event Action<string, string, string>? OnNotificationRaised;

        public RansomwareEnforcementHandler(
            IQuarantineService? quarantineService = null,
            ISecurityFindingService? findingService = null,
            IAuditLogService? auditLogService = null,
            ILogger? logger = null)
        {
            _quarantineService = quarantineService;
            _findingService = findingService;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(
            string offendingPath,
            string reason,
            int riskScore,
            int pid = 0,
            Func<string, bool>? isAppAllowed = null)
        {
            Interlocked.Increment(ref _totalBlockedCount);

            int targetPid = pid;
            string targetProcName = "Bilinmeyen Süreç";
            string targetProcPath = string.Empty;
            bool processTerminated = false;

            // 1. Identify offending process locking the file or recent processes
            try
            {
                var processes = Process.GetProcesses();
                foreach (var p in processes)
                {
                    try
                    {
                        if (p.Id <= 4 || p.Id == Environment.ProcessId || CriticalProcesses.IsCriticalProcess(p.ProcessName)) continue;
                        if (isAppAllowed != null && (isAppAllowed(p.ProcessName) || isAppAllowed(p.MainModule?.FileName ?? ""))) continue;

                        if (targetPid > 0 && p.Id == targetPid)
                        {
                            targetProcName = p.ProcessName;
                            targetProcPath = p.MainModule?.FileName ?? "";
                            break;
                        }

                        if (string.Equals(p.MainModule?.FileName, offendingPath, StringComparison.OrdinalIgnoreCase))
                        {
                            targetPid = p.Id;
                            targetProcName = p.ProcessName;
                            targetProcPath = p.MainModule?.FileName ?? "";
                            break;
                        }
                    }
                    catch { }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch { }

            // 2. Active Process Termination if High/Critical Risk
            if (riskScore >= 70 && targetPid > 4 && targetPid != Environment.ProcessId && !CriticalProcesses.IsCriticalProcess(targetProcName) && !FileScannerService.IsSelfOwnedPath(targetProcPath))
            {
                try
                {
                    using var procToKill = Process.GetProcessById(targetPid);
                    if (!procToKill.HasExited)
                    {
                        procToKill.Kill(entireProcessTree: true);
                        procToKill.WaitForExit(1500);
                        processTerminated = true;
                        _logger?.LogWarning("Ransomware offending process terminated: {Proc} (PID: {Pid})", targetProcName, targetPid);
                    }
                }
                catch { }
            }

            // 3. Quarantine Source Binary if path exists
            if (!string.IsNullOrEmpty(targetProcPath) && File.Exists(targetProcPath) && !FileScannerService.IsSelfOwnedPath(targetProcPath) && _quarantineService != null)
            {
                try
                {
                    await _quarantineService.QuarantineFileAsync(targetProcPath, $"Ransomware Activity: {reason}");
                }
                catch { }
            }

            // 4. Create Security Incident
            var assessment = new RansomwareDamageAssessment
            {
                FilesTargeted = 1,
                FilesModified = 1,
                FilesBlocked = _totalBlockedCount,
                OffendingProcess = targetProcName,
                IncidentTime = DateTime.UtcNow
            };

            var alertArgs = new RansomwareAlertEventArgs
            {
                OffendingFilePath = offendingPath,
                OffendingProcessName = targetProcName,
                OffendingProcessId = targetPid,
                DetectionReason = reason,
                RiskScore = riskScore,
                ProcessTerminated = processTerminated,
                FilesAffected = assessment.FilesTargeted,
                Timestamp = DateTime.UtcNow
            };

            OnRansomwareAttemptDetected?.Invoke(this, alertArgs);

            string toastTitle = processTerminated ? "🛑 Fidye Saldırısı Durduruldu ve Süreç Kapatıldı!" : "🚨 Fidye Kalkanı Tehdit Uyarısı!";
            string toastMsg = processTerminated
                ? $"'{targetProcName}' süreci durduruldu. {reason}"
                : $"Korunan klasörde şüpheli şifreleme girişimi engellendi: '{Path.GetFileName(offendingPath)}'";

            OnNotificationRaised?.Invoke(toastTitle, toastMsg, "Danger");

            if (_auditLogService != null)
            {
                await _auditLogService.LogActionAsync(
                    AuditAction.ProcessTerminated,
                    "RansomwareShield",
                    targetProcName,
                    offendingPath,
                    $"{reason} - Skor: {riskScore}/100 - Süreç Sonlandırıldı: {processTerminated}",
                    AuditResult.Success);
            }

            return assessment;
        }
    }
}
