using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Windows Kernel Process ve Komut Satırı Telemetrisi (ETW / WMI Trace) İzleme Servisi.
    /// Süreç oluşturulduğu anda komut satırı argümanlarını analiz eder ve MITRE ATT&CK tekniklerini yakalar.
    /// </summary>
    public class EtwProcessMonitorService : IEtwProcessMonitorService
    {
        private readonly ILogger<EtwProcessMonitorService>? _logger;
        private readonly IAuditLogService? _auditLogService;
        private readonly object _lock = new();
        private ManagementEventWatcher? _processStartWatcher;
        private CancellationTokenSource? _cts;
        private bool _isRunning;

        public bool IsRunning => _isRunning;
        public event Action<EtwProcessEvent>? ProcessCreated;
        public event Action<EtwThreatAlert>? ThreatDetected;

        // MITRE ATT&CK ve Yüksek Riskli Komut Satırı Kuralları
        private static readonly (string RuleName, string ThreatName, int Score, string Pattern, string MitreTechnique, string Action)[] CommandRules = new[]
        {
            // T1059.001 - PowerShell Gizlenmiş Komut Yürütme
            ("ETW_POWERSHELL_ENCODED", "Gizlenmiş PowerShell Yürütme (Base64)", 95,
             @"(?i)(powershell|pwsh)(\.exe)?\s+.*(-e|-enc|-encodedcommand|-encoded)\s+[a-zA-Z0-9+/=]{10,}",
             "T1059.001", "Terminate"),

            // T1059.001 - PowerShell Bellek İçi İndirme ve Çalıştırma (Download Cradle)
            ("ETW_POWERSHELL_DOWNLOAD_CRADLE", "Bellek İçi Zararlı İndirme Beşiği (Download Cradle)", 95,
             @"(?i)(powershell|pwsh)(\.exe)?\s+.*(DownloadString|DownloadFile|DownloadData|IEX|Invoke-Expression|Net\.WebClient|HttpClient|Invoke-WebRequest)",
             "T1059.001", "Terminate"),

            // T1059.003 - PowerShell Gizleme & İlke Atlama Bayrakları
            ("ETW_POWERSHELL_EVASION_FLAGS", "Gizlenmiş ve Korumasız PowerShell Oturumu", 90,
             @"(?i)(powershell|pwsh)(\.exe)?\s+.*(-w\s+hidden|-windowstyle\s+hidden).*(-nop|-noprofile).*(-ep\s+bypass|-executionpolicy\s+bypass)",
             "T1059.003", "Terminate"),

            // T1490 - Gölge Kopyaların ve Yedeklerin Silinmesi (Ransomware Hazırlığı)
            ("ETW_SHADOW_COPY_DELETION", "Gölge Kopya ve Yedek İmha Girişimi (Fidye Yazılımı)", 100,
             @"(?i)(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+catalog|bcdedit(\.exe)?\s+/set\s+.*bootstatuspolicy\s+ignoreallfailures)",
             "T1490", "Terminate"),

            // T1003.001 - LSASS Bellek Okuma ve Şifre Hırsızlığı
            ("ETW_LSASS_CREDENTIAL_DUMP", "LSASS Bellek Dökümü ve Kimlik Bilgisi Hırsızlığı", 100,
             AegisPC.Security.Common.SecObfuscator.Unmask(new byte[] { 114, 101, 51, 115, 114, 42, 40, 53, 57, 62, 47, 55, 42, 114, 6, 116, 63, 34, 63, 115, 101, 6, 41, 113, 116, 112, 119, 55, 59, 6, 41, 113, 116, 112, 54, 41, 59, 41, 41, 38, 57, 53, 55, 41, 44, 57, 41, 6, 116, 62, 54, 54, 6, 41, 112, 118, 101, 6, 41, 112, 121, 101, 104, 110, 6, 41, 113, 116, 112, 54, 41, 59, 41, 41, 38, 55, 51, 55, 51, 49, 59, 46, 32, 38, 41, 63, 49, 47, 40, 54, 41, 59, 38, 62, 47, 55, 42, 63, 40, 46, 115 }),
             "T1003.001", "Terminate"),

            // T1562.001 - Güvenlik Araçlarını ve Defender'ı Devre Dışı Bırakma
            ("ETW_DEFENDER_TAMPER_ATTEMPT", "Antivirüs ve Güvenlik Kalkanını Devre Dışı Bırakma Girişimi", 95,
             AegisPC.Security.Common.SecObfuscator.Unmask(new byte[] { 114, 101, 51, 115, 114, 9, 63, 46, 119, 23, 42, 10, 40, 63, 60, 63, 40, 63, 52, 57, 63, 6, 41, 113, 116, 112, 119, 30, 51, 41, 59, 56, 54, 63, 8, 63, 59, 54, 46, 51, 55, 63, 23, 53, 52, 51, 46, 53, 40, 51, 52, 61, 6, 41, 113, 6, 14, 40, 47, 63, 38, 41, 57, 114, 6, 116, 63, 34, 63, 115, 101, 6, 41, 113, 41, 46, 53, 42, 6, 41, 113, 13, 51, 52, 30, 63, 60, 63, 52, 62, 38, 52, 63, 46, 114, 6, 116, 63, 34, 63, 115, 101, 6, 41, 113, 41, 46, 53, 42, 6, 41, 113, 114, 13, 51, 52, 30, 63, 60, 63, 52, 62, 38, 9, 63, 57, 47, 40, 51, 46, 35, 18, 63, 59, 54, 46, 50, 9, 63, 40, 44, 51, 57, 63, 38, 45, 47, 59, 47, 41, 63, 40, 44, 115, 115 }),
             "T1562.001", "Terminate"),

            // T1053.005 - Zamanlanmış Görev ile Kalıcılık / Arka Kapı
            ("ETW_SCHTASKS_PERSISTENCE", "Zamanlanmış Görev ile Kalıcılık / Arka Kapı", 90,
             @"(?i)schtasks(\.exe)?\s+.*(/create|/change)\s+.*(/tr\s+.*(cmd|powershell|cscript|wscript|mshta|regsvr32|rundll32|temp))",
             "T1053.005", "Terminate"),

            // T1547.001 - Kayıt Defteri Başlangıç Anahtarı Enjeksiyonu
            ("ETW_REG_RUN_PERSISTENCE", "Kayıt Defteri Başlangıç Anahtarı Enjeksiyonu (Reg.exe)", 85,
             @"(?i)reg(\.exe)?\s+add\s+.*(currentversion\\run|currentversion\\runonce)\s+/v",
             "T1547.001", "Terminate"),

            // T1105 - Certutil veya Bitsadmin ile Zararlı İndirme
            ("ETW_CERTUTIL_DOWNLOAD", "CertUtil / BITSAdmin ile Dosya İndirme (Living Off The Land)", 90,
             @"(?i)(certutil(\.exe)?\s+.*(-urlcache|-split)\s+.*http|bitsadmin(\.exe)?\s+/transfer\s+.*http)",
             "T1105", "Terminate"),

            // T1218.011 - Rundll32 / Regsvr32 Şüpheli Komut Satırı
            ("ETW_SQUIPLYDOO_SCRIPTLET", "Regsvr32 / Rundll32 Uzaktan Betik Yürütme (Squiblydoo)", 95,
             @"(?i)(regsvr32(\.exe)?\s+.*(/s\s+/n\s+/u\s+/i:http|scrobj\.dll)|mshta(\.exe)?\s+.*(http|javascript:|vbscript:))",
             "T1218.011", "Terminate"),

            // T1036.005 - Çift Uzantılı Dosya Yürütme (.pdf.exe, .xlsx.cmd)
            ("ETW_DOUBLE_EXTENSION_EXEC", "Çift Uzantılı Şüpheli Yürütme", 85,
             @"(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|csv)\.(exe|cmd|bat|vbs|js|ps1|hta|scr)",
             "T1036.005", "Terminate")
        };

        private ManagementEventWatcher? _processStopWatcher;

        public EtwProcessMonitorService(
            ILogger<EtwProcessMonitorService>? logger = null,
            IAuditLogService? auditLogService = null)
        {
            _logger = logger;
            _auditLogService = auditLogService;
        }

        public void Start()
        {
            lock (_lock)
            {
                if (_isRunning) return;
                _isRunning = true;
                _cts = new CancellationTokenSource();

                _logger?.LogInformation("Starting Real-Time ETW / Process Telemetry Monitor Service...");

                try
                {
                    // 1. Hook Kernel Process Start Event Trace (Event-Driven, Zero-Polling Latency)
                    var startQuery = new EventQuery("SELECT * FROM Win32_ProcessStartTrace");
                    _processStartWatcher = new ManagementEventWatcher(startQuery);
                    _processStartWatcher.EventArrived += OnProcessStartTrace;
                    _processStartWatcher.Start();

                    // 2. Hook Kernel Process Stop Event Trace (Process Termination Tracking)
                    try
                    {
                        var stopQuery = new EventQuery("SELECT * FROM Win32_ProcessStopTrace");
                        _processStopWatcher = new ManagementEventWatcher(stopQuery);
                        _processStopWatcher.EventArrived += OnProcessStopTrace;
                        _processStopWatcher.Start();
                    }
                    catch { }

                    _logger?.LogInformation("Real-Time Process Start Trace Provider hooked successfully (Zero-Latency ETW Mode).");
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "WMI Process Trace hook failed (Non-admin or restricted). Falling back to WQL InstanceCreation provider.");
                    try
                    {
                        var query = new WqlEventQuery("__InstanceCreationEvent", TimeSpan.FromMilliseconds(500), "TargetInstance ISA 'Win32_Process'");
                        _processStartWatcher = new ManagementEventWatcher(query);
                        _processStartWatcher.EventArrived += OnProcessInstanceCreation;
                        _processStartWatcher.Start();
                    }
                    catch (Exception ex2)
                    {
                        _logger?.LogWarning(ex2, "WQL fallback failed. Starting lightweight high-speed polling monitor.");
                        StartPollingFallback(_cts.Token);
                    }
                }
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning) return;
                _isRunning = false;

                try
                {
                    _cts?.Cancel();
                    _processStartWatcher?.Stop();
                    _processStartWatcher?.Dispose();
                    _processStartWatcher = null;

                    _processStopWatcher?.Stop();
                    _processStopWatcher?.Dispose();
                    _processStopWatcher = null;
                }
                catch { }

                _logger?.LogInformation("Stopped Real-Time ETW / Process Telemetry Monitor Service.");
            }
        }

        private void OnProcessStartTrace(object sender, EventArrivedEventArgs e)
        {
            try
            {
                int pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                int ppid = Convert.ToInt32(e.NewEvent["ParentProcessID"]);
                string name = e.NewEvent["ProcessName"]?.ToString() ?? string.Empty;
                string cmdLine = GetCommandLineForPid(pid, name);

                var procEvent = new EtwProcessEvent
                {
                    ProcessId = pid,
                    ParentProcessId = ppid,
                    ImageFileName = name,
                    CommandLine = cmdLine,
                    Timestamp = DateTime.UtcNow
                };

                ProcessCreated?.Invoke(procEvent);

                // Immediate Threat Evaluation
                var alert = EvaluateCommandLine(pid, name, cmdLine, ppid);
                if (alert != null)
                {
                    MitigateThreat(alert);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error handling process start trace event");
            }
        }

        private void OnProcessStopTrace(object sender, EventArrivedEventArgs e)
        {
            try
            {
                int pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                // Can be hooked by lineage tracker to mark process terminated
            }
            catch { }
        }

        private void OnProcessInstanceCreation(object sender, EventArrivedEventArgs e)
        {
            try
            {
                if (e.NewEvent["TargetInstance"] is ManagementBaseObject targetInstance)
                {
                    int pid = Convert.ToInt32(targetInstance["ProcessId"]);
                    int ppid = Convert.ToInt32(targetInstance["ParentProcessId"]);
                    string name = targetInstance["Name"]?.ToString() ?? string.Empty;
                    string cmdLine = targetInstance["CommandLine"]?.ToString() ?? string.Empty;

                    var procEvent = new EtwProcessEvent
                    {
                        ProcessId = pid,
                        ParentProcessId = ppid,
                        ImageFileName = name,
                        CommandLine = cmdLine,
                        Timestamp = DateTime.UtcNow
                    };

                    ProcessCreated?.Invoke(procEvent);

                    var alert = EvaluateCommandLine(pid, name, cmdLine, ppid);
                    if (alert != null)
                    {
                        MitigateThreat(alert);
                    }
                }
            }
            catch { }
        }

        private string GetCommandLineForPid(int pid, string fallbackName)
        {
            if (pid <= 4) return fallbackName;

            try
            {
                using var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                using var results = searcher.Get();
                foreach (ManagementObject obj in results)
                {
                    var cmd = obj["CommandLine"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(cmd)) return cmd;
                }
            }
            catch { }

            return fallbackName;
        }

        public EtwThreatAlert? EvaluateCommandLine(int pid, string processName, string commandLine, int parentPid = 0)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
            {
                commandLine = processName;
            }

            foreach (var (ruleName, threatName, score, pattern, mitre, action) in CommandRules)
            {
                try
                {
                    if (Regex.IsMatch(commandLine, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    {
                        var alert = new EtwThreatAlert
                        {
                            RuleName = ruleName,
                            ThreatName = threatName,
                            SeverityScore = score,
                            ProcessId = pid,
                            ProcessName = processName,
                            CommandLine = commandLine,
                            MitigationAction = action,
                            Timestamp = DateTime.UtcNow
                        };

                        _logger?.LogWarning("🚨 [ETW THREAT DETECTED] Rule: {Rule} ({Threat}) | PID: {Pid} | MITRE: {Mitre} | Cmd: {Cmd}",
                            ruleName, threatName, pid, mitre, commandLine);

                        _auditLogService?.LogActionAsync(
                            AegisPC.Core.Enums.AuditAction.ProcessTerminated,
                            "ETW_THREAT",
                            processName,
                            null,
                            $"{threatName} (MITRE: {mitre}) - PID: {pid}, Komut: {commandLine}");

                        ThreatDetected?.Invoke(alert);
                        return alert;
                    }
                }
                catch { }
            }

            return null;
        }

        private void MitigateThreat(EtwThreatAlert alert)
        {
            if (alert.ProcessId <= 4) return; // System processes protection

            try
            {
                using var proc = Process.GetProcessById(alert.ProcessId);
                if (!proc.HasExited)
                {
                    proc.Kill(entireProcessTree: true);
                    _logger?.LogInformation("🛡️ [ETW MITIGATION] Process Tree Terminated: PID {Pid} ({Name})", alert.ProcessId, proc.ProcessName);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Could not terminate offending process PID {Pid}", alert.ProcessId);
            }
        }

        private void StartPollingFallback(CancellationToken ct)
        {
            Task.Run(async () =>
            {
                var knownPids = new HashSet<int>(Process.GetProcesses().Select(p => p.Id));

                while (!ct.IsCancellationRequested && _isRunning)
                {
                    try
                    {
                        var currentProcs = Process.GetProcesses();
                        var currentPidSet = new HashSet<int>();

                        foreach (var proc in currentProcs)
                        {
                            try
                            {
                                int pid = proc.Id;
                                currentPidSet.Add(pid);

                                if (!knownPids.Contains(pid) && pid > 4)
                                {
                                    string name = proc.ProcessName;
                                    string cmdLine = name; // In non-WMI fallback, fallback to process name

                                    var alert = EvaluateCommandLine(pid, name, cmdLine);
                                    if (alert != null)
                                    {
                                        MitigateThreat(alert);
                                    }
                                }
                            }
                            catch { }
                            finally
                            {
                                proc.Dispose();
                            }
                        }

                        knownPids = currentPidSet;
                    }
                    catch { }

                    await Task.Delay(250, ct).ConfigureAwait(false);
                }
            }, ct);
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
