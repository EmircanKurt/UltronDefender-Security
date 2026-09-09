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
            Func<string, bool>? isAppAllowed = null,
            DateTime? incidentTimestamp = null);
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
            Func<string, bool>? isAppAllowed = null,
            DateTime? incidentTimestamp = null)
        {
            var incidentTime = incidentTimestamp ?? DateTime.UtcNow;
            Interlocked.Increment(ref _totalBlockedCount);

            int targetPid = 0;
            string targetProcName = "Bilinmeyen Süreç";
            string targetProcPath = string.Empty;
            bool processTerminated = false;

            // 1. PID Adaylarını Belirle:
            // A. Eğer arayan doğrudan PID verdiyse onu değerlendir
            // B. Eğer pid verilmediyse (0 ise) Restart Manager ile dosyayı kilitleyen süreci bul
            var candidatePids = new List<int>();
            if (pid > 0)
            {
                candidatePids.Add(pid);
            }
            else if (!string.IsNullOrWhiteSpace(offendingPath))
            {
                try
                {
                    var lockingPids = FileLockProcessResolver.FindLockingProcessIds(offendingPath);
                    if (lockingPids.Count > 0)
                    {
                        candidatePids.AddRange(lockingPids);
                    }
                }
                catch { }
            }

            // 2. Aday Süreçleri Güvenlik Kalkanı ve PID-Reuse Filtresinden Geçir
            foreach (var candPid in candidatePids)
            {
                // Kritik PID Kontrolü (System Idle Process, System, vb.)
                if (candPid <= 4 || candPid == Environment.ProcessId)
                {
                    _logger?.LogDebug("Skipping PID {Pid}: Core system or current process.", candPid);
                    continue;
                }

                try
                {
                    using var proc = Process.GetProcessById(candPid);
                    if (proc.HasExited)
                    {
                        _logger?.LogDebug("Skipping PID {Pid}: Process has already exited.", candPid);
                        continue;
                    }

                    string procName = proc.ProcessName;

                    // Kritik Süreç İsim Filtresi (explorer, svchost, csrss, dwm, etc.)
                    if (CriticalProcesses.IsCriticalProcess(procName))
                    {
                        _logger?.LogWarning("Threat associated with critical process '{Proc}' (PID: {Pid}). Termination blocked for system stability.", procName, candPid);
                        targetProcName = procName;
                        continue;
                    }

                    // Süreç Dosya Yolu Alımı
                    string procPath = string.Empty;
                    try
                    {
                        procPath = proc.MainModule?.FileName ?? string.Empty;
                    }
                    catch { }

                    // Öz-Koruma: Antivirüs ve koruma süreçleri asla öldürülmez
                    if (!string.IsNullOrEmpty(procPath) && FileScannerService.IsSelfOwnedPath(procPath))
                    {
                        _logger?.LogDebug("Skipping PID {Pid}: Self-owned protection binary.", candPid);
                        continue;
                    }

                    // İzinli / Güvenilir Uygulama Filtresi (Controlled Folder Access Allowlist)
                    if (isAppAllowed != null && (isAppAllowed(procName) || (!string.IsNullOrEmpty(procPath) && isAppAllowed(procPath))))
                    {
                        _logger?.LogInformation("Skipping PID {Pid}: Application '{Proc}' is allowed to access protected folders.", candPid, procName);
                        continue;
                    }

                    // PID-Reuse Koruması (StartTime Check):
                    // Süreç, olay tespit zamanından sonra başlamışsa bu PID işletim sistemi tarafından başka bir sürece atanmış demektir.
                    try
                    {
                        var procStartTime = proc.StartTime.ToUniversalTime();
                        if (procStartTime > incidentTime.AddSeconds(2))
                        {
                            _logger?.LogWarning("PID reuse guard tripped! Process '{Proc}' (PID: {Pid}) started at {Start}, which is after incident time {Incident}. Termination aborted.",
                                procName, candPid, procStartTime, incidentTime);
                            continue;
                        }
                    }
                    catch { }

                    // Windows Sistem Dizinleri Koruması (System32, SysWOW64, WinSxS)
                    if (!string.IsNullOrEmpty(procPath))
                    {
                        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                        string sys32 = Path.Combine(winDir, "System32");
                        string syswow = Path.Combine(winDir, "SysWOW64");
                        string winsxs = Path.Combine(winDir, "WinSxS");

                        bool isSystemBinary = procPath.StartsWith(sys32, StringComparison.OrdinalIgnoreCase) ||
                                              procPath.StartsWith(syswow, StringComparison.OrdinalIgnoreCase) ||
                                              procPath.StartsWith(winsxs, StringComparison.OrdinalIgnoreCase);

                        if (isSystemBinary && (CriticalProcesses.IsCriticalProcess(procName) || CriticalProcesses.IsCriticalProcess(Path.GetFileName(procPath))))
                        {
                            _logger?.LogWarning("Refusing to terminate core Windows system binary: {Path}", procPath);
                            targetProcName = procName;
                            continue;
                        }
                    }

                    // Güvenlik kontrollerini geçen ilk doğrulanmış saldırgan süreç
                    targetPid = candPid;
                    targetProcName = procName;
                    targetProcPath = procPath;
                    break;
                }
                catch (ArgumentException)
                {
                    // Süreç arama sırasında sonlanmış
                }
                catch (Exception ex)
                {
                    _logger?.LogDebug(ex, "Error inspecting candidate process {Pid}", candPid);
                }
            }

            // 3. Yüksek/Kritik Riskte Aktif Güvenli Süreç İnfazı (Kill)
            if (riskScore >= 70 && targetPid > 4 && targetPid != Environment.ProcessId)
            {
                try
                {
                    using var procToKill = Process.GetProcessById(targetPid);
                    if (!procToKill.HasExited)
                    {
                        // İnfazdan hemen önce yarış durumuna karşı son StartTime doğrulaması
                        try
                        {
                            if (procToKill.StartTime.ToUniversalTime() > incidentTime.AddSeconds(2))
                            {
                                throw new InvalidOperationException("PID reuse detected immediately before termination.");
                            }
                        }
                        catch (InvalidOperationException) { throw; }
                        catch { }

                        procToKill.Kill(entireProcessTree: true);
                        procToKill.WaitForExit(1500);
                        processTerminated = true;
                        _logger?.LogWarning("Ransomware offending process successfully terminated: {Proc} (PID: {Pid})", targetProcName, targetPid);
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to terminate offending process {Proc} (PID: {Pid})", targetProcName, targetPid);
                }
            }

            // 4. Saldırgan İkiliyi (Source Binary) Karantinaya Al
            if ((processTerminated || riskScore >= 90) &&
                !string.IsNullOrEmpty(targetProcPath) &&
                File.Exists(targetProcPath) &&
                !FileScannerService.IsSelfOwnedPath(targetProcPath) &&
                _quarantineService != null)
            {
                try
                {
                    await _quarantineService.QuarantineFileAsync(targetProcPath, $"Ransomware Activity: {reason}");
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to quarantine ransomware binary {Path}", targetProcPath);
                }
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
