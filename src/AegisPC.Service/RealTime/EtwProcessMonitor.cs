using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.RealTime
{
    public record ProcessStartTelemetry
    {
        public int ProcessId { get; init; }
        public int ParentProcessId { get; init; }
        public string ImageFileName { get; init; } = string.Empty;
        public string CommandLine { get; init; } = string.Empty;
        public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
        public bool IsSuspiciousLolbas { get; init; }
        public string ThreatReason { get; init; } = string.Empty;
    }

    public record ProcessStopTelemetry
    {
        public int ProcessId { get; init; }
        public int ExitCode { get; init; }
        public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Microsoft-Windows-Kernel-Process ETW Sağlayıcısı üzerinden gerçek zamanlı
    /// süreç başlatma (ProcessStart), süreç sonlandırma (ProcessExit) ve çıkış zamanı (ProcessExitTime)
    /// telemetri motoru.
    /// 256 MB döngüsel bellek (circular buffer), C:\ProgramData\UltronDefender\EtwLogs\ dizinine yerel ETL/log kaydı,
    /// IBehaviorEngine ve ISecurityFindingService entegrasyonu sunar.
    /// </summary>
    public class EtwProcessMonitor : IDisposable
    {
        private readonly ILogger<EtwProcessMonitor>? _logger;
        private readonly IProcessLineageTracker? _lineageTracker;
        private readonly IAuditLogService? _auditLogService;
        private readonly IBehaviorEngine? _behaviorEngine;
        private readonly ISecurityFindingService? _findingService;

        private TraceEventSession? _session;
        private Task? _processingTask;
        private CancellationTokenSource? _cts;
        private bool _isRunning;
        private readonly object _lock = new();

        public static readonly Guid KernelProcessProviderGuid = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
        public const string DefaultSessionName = "AegisPCEtwSession";
        public const string DefaultLogDirectory = @"C:\ProgramData\UltronDefender\EtwLogs";
        private const int DefaultBufferSizeMB = 256;

        private StreamWriter? _etlLogWriter;
        private readonly object _logLock = new();

        public bool IsRunning => _isRunning;

        public event Action<ProcessStartTelemetry>? ProcessStarted;
        public event Action<ProcessStopTelemetry>? ProcessStopped;

        public EtwProcessMonitor(
            ILogger<EtwProcessMonitor>? logger = null,
            IProcessLineageTracker? lineageTracker = null,
            IAuditLogService? auditLogService = null,
            IBehaviorEngine? behaviorEngine = null,
            ISecurityFindingService? findingService = null)
        {
            _logger = logger;
            _lineageTracker = lineageTracker;
            _auditLogService = auditLogService;
            _behaviorEngine = behaviorEngine;
            _findingService = findingService;
        }

        public void Start()
        {
            lock (_lock)
            {
                if (_isRunning) return;
                _isRunning = true;
                _cts = new CancellationTokenSource();

                _logger?.LogInformation("Starting ETW Process Monitor (Session: {Session}, Buffer: {Buffer}MB)...",
                    DefaultSessionName, DefaultBufferSizeMB);

                try
                {
                    // 1. Günlük Dizini Hazırlığı (C:\ProgramData\UltronDefender\EtwLogs\)
                    try
                    {
                        if (!Directory.Exists(DefaultLogDirectory))
                        {
                            Directory.CreateDirectory(DefaultLogDirectory);
                        }

                        string logFilePath = Path.Combine(DefaultLogDirectory, "ProcessEvents.log");
                        var fs = new FileStream(logFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                        _etlLogWriter = new StreamWriter(fs, Encoding.UTF8) { AutoFlush = true };
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning(ex, "Could not initialize local ETW log file at {Dir}. Continuing in-memory.", DefaultLogDirectory);
                    }

                    // 2. Önceki artık oturum varsa güvenle temizle
                    try
                    {
                        var existingSession = TraceEventSession.GetActiveSession(DefaultSessionName);
                        existingSession?.Dispose();
                    }
                    catch { }

                    // 3. 256 MB Döngüsel Bellek (Circular Buffer) ile Gerçek Zamanlı ETW Oturumu
                    _session = new TraceEventSession(DefaultSessionName, TraceEventSessionOptions.Create)
                    {
                        BufferSizeMB = DefaultBufferSizeMB,
                        CircularBufferMB = DefaultBufferSizeMB,
                        StopOnDispose = true
                    };

                    // MatchAnyKeywords: 0x10 = WINEVENT_KEYWORD_PROCESS (ProcessStart, ProcessStop, ProcessExit)
                    _session.EnableProvider(
                        KernelProcessProviderGuid,
                        TraceEventLevel.Informational,
                        matchAnyKeywords: 0x10);

                    // 4. Olay Dinleyicisi Tanımlama
                    _session.Source.Dynamic.All += OnKernelProcessEvent;

                    // 5. Arka Plan Dinleme Görevi
                    _processingTask = Task.Factory.StartNew(
                        () =>
                        {
                            try
                            {
                                _session.Source.Process();
                            }
                            catch (Exception ex)
                            {
                                _logger?.LogDebug(ex, "ETW Process message pump terminated.");
                            }
                        },
                        _cts.Token,
                        TaskCreationOptions.LongRunning,
                        TaskScheduler.Default);

                    _logger?.LogInformation("ETW Process Monitor active and listening to Microsoft-Windows-Kernel-Process.");
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to start ETW Process Monitor session (non-admin rights or session limit). Progressive fallback active.");
                    _isRunning = false;
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
                    _session?.Stop();
                    _session?.Dispose();
                    _session = null;
                }
                catch (Exception ex)
                {
                    _logger?.LogTrace(ex, "Error stopping ETW Process Monitor session.");
                }
                finally
                {
                    _cts?.Dispose();
                    _cts = null;

                    lock (_logLock)
                    {
                        try
                        {
                            _etlLogWriter?.Flush();
                            _etlLogWriter?.Dispose();
                            _etlLogWriter = null;
                        }
                        catch { }
                    }
                }

                _logger?.LogInformation("ETW Process Monitor stopped.");
            }
        }

        private void OnKernelProcessEvent(TraceEvent data)
        {
            if (!_isRunning) return;

            try
            {
                string eventName = data.EventName;
                bool isStart = eventName.Contains("ProcessStart", StringComparison.OrdinalIgnoreCase) ||
                               eventName.Contains("Start", StringComparison.OrdinalIgnoreCase);
                bool isStop = eventName.Contains("ProcessStop", StringComparison.OrdinalIgnoreCase) ||
                              eventName.Contains("ProcessExit", StringComparison.OrdinalIgnoreCase) ||
                              eventName.Contains("Stop", StringComparison.OrdinalIgnoreCase);

                DateTime timestampUtc = data.TimeStamp.Kind == DateTimeKind.Utc
                    ? data.TimeStamp
                    : data.TimeStamp.ToUniversalTime();

                if (isStart)
                {
                    int pid = data.ProcessID;
                    if (pid <= 4) return; // System idle / kernel bypass

                    string imagePath = ExtractPayloadString(data, "ImageFileName", "FileName", "ImageName");
                    string commandLine = ExtractPayloadString(data, "CommandLine", "CommandLineString");
                    int ppid = 0;

                    var ppidPayload = data.PayloadByName("ParentProcessID") ?? data.PayloadByName("ParentPID");
                    if (ppidPayload is int ppidVal) ppid = ppidVal;
                    else if (ppidPayload != null && int.TryParse(ppidPayload.ToString(), out int parsedPpid)) ppid = parsedPpid;

                    // 1. Yerel Log Dosyasına Yaz (C:\ProgramData\UltronDefender\EtwLogs\ProcessEvents.log)
                    WriteToLocalLog($"[START] {timestampUtc:yyyy-MM-dd HH:mm:ss.fff} | PID: {pid} | PPID: {ppid} | Image: {imagePath} | Cmd: {commandLine}");

                    // 2. Süreç Soy Ağacına Kaydet (ProcessLineageTracker)
                    if (_lineageTracker != null && !string.IsNullOrWhiteSpace(imagePath))
                    {
                        try
                        {
                            _lineageTracker.RegisterProcess(new ProcessNode
                            {
                                Pid = pid,
                                ParentPid = ppid,
                                ExecutablePath = imagePath,
                                ProcessName = Path.GetFileName(imagePath),
                                CommandLine = commandLine,
                                StartTimeUtc = timestampUtc
                            });
                        }
                        catch { }
                    }

                    // 3. Davranış Motoruna Besle (BehaviorEngine.ProcessEventAsync)
                    if (_behaviorEngine != null)
                    {
                        try
                        {
                            var behaviorEvent = new BehaviorEvent
                            {
                                EventType = ppid > 0 ? BehaviorEventType.ChildProcessSpawn : BehaviorEventType.ProcessSpawn,
                                ProcessId = pid,
                                ParentProcessId = ppid,
                                ProcessName = Path.GetFileName(imagePath),
                                ExecutablePath = imagePath,
                                CommandLine = commandLine,
                                Timestamp = timestampUtc,
                                Details = $"ETW ProcessStart detected. PPID: {ppid}, Image: {imagePath}"
                            };
                            _ = _behaviorEngine.ProcessEventAsync(behaviorEvent);
                        }
                        catch { }
                    }

                    // 4. LOLBAS ve Şüpheli Komut Satırı Analizi
                    bool isSuspicious = CheckSuspiciousCommandLine(imagePath, commandLine, out string reason);

                    var telemetry = new ProcessStartTelemetry
                    {
                        ProcessId = pid,
                        ParentProcessId = ppid,
                        ImageFileName = imagePath,
                        CommandLine = commandLine,
                        TimestampUtc = timestampUtc,
                        IsSuspiciousLolbas = isSuspicious,
                        ThreatReason = reason
                    };

                    // 5. Şüpheli Davranış Bulunduysa SecurityFinding Oluştur ve Servise Bildir
                    if (isSuspicious)
                    {
                        _logger?.LogWarning("SECURITY ALERT: Suspicious Process/LOLBAS Activity! PID: {Pid}, Exe: {Exe}, Reason: {Reason}",
                            pid, imagePath, reason);

                        WriteToLocalLog($"[SECURITY_ALERT] PID: {pid} | Threat: {reason} | Exe: {imagePath}");

                        if (_findingService != null)
                        {
                            var finding = new SecurityFinding
                            {
                                Id = Guid.NewGuid(),
                                ObjectPath = imagePath,
                                ObjectName = Path.GetFileName(imagePath),
                                RiskLevel = RiskLevel.ConfirmedMalicious,
                                RiskScore = 95,
                                Category = FindingCategory.MalwareSuspicion,
                                Title = $"LOLBAS / Ransomware Behavior: {reason}",
                                Description = $"Suspicious process execution detected via ETW. PID: {pid}, PPID: {ppid}, Exe: {imagePath}, Command: {commandLine}",
                                RiskReasons = new List<string> { reason, $"Command: {commandLine}", $"Parent PID: {ppid}" },
                                ConfidenceLevel = ConfidenceLevel.High,
                                FirstObserved = timestampUtc,
                                LastObserved = timestampUtc,
                                CreatedAt = timestampUtc,
                                UpdatedAt = timestampUtc,
                                Status = FindingStatus.Active
                            };

                            _ = _findingService.AddFindingAsync(finding);
                        }
                    }

                    ProcessStarted?.Invoke(telemetry);
                }
                else if (isStop)
                {
                    int pid = data.ProcessID;
                    int exitCode = 0;
                    var exitCodePayload = data.PayloadByName("ExitCode");
                    if (exitCodePayload is int ec) exitCode = ec;

                    WriteToLocalLog($"[EXIT]  {timestampUtc:yyyy-MM-dd HH:mm:ss.fff} | PID: {pid} | ExitCode: {exitCode}");

                    if (_lineageTracker != null)
                    {
                        try
                        {
                            _lineageTracker.MarkTerminated(pid);
                        }
                        catch { }
                    }

                    ProcessStopped?.Invoke(new ProcessStopTelemetry
                    {
                        ProcessId = pid,
                        ExitCode = exitCode,
                        TimestampUtc = timestampUtc
                    });
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error parsing ETW process event.");
            }
        }

        private void WriteToLocalLog(string entry)
        {
            if (_etlLogWriter == null) return;
            lock (_logLock)
            {
                try
                {
                    _etlLogWriter.WriteLine(entry);
                }
                catch { }
            }
        }

        public static bool CheckSuspiciousCommandLine(string imagePath, string commandLine, out string reason)
        {
            reason = string.Empty;
            if (string.IsNullOrWhiteSpace(commandLine)) return false;

            string cmdLower = commandLine.ToLowerInvariant();
            string exeName = Path.GetFileName(imagePath).ToLowerInvariant();

            // 1. Fidye Yazılımı (Ransomware) Gölge Kopya ve Yedek Silme Girişimleri
            if (cmdLower.Contains("vssadmin") && (cmdLower.Contains("delete") || cmdLower.Contains("shadows")))
            {
                reason = "Ransomware Behavior: VSS Shadow Copy Deletion (vssadmin delete shadows)";
                return true;
            }
            if (cmdLower.Contains("wmic") && cmdLower.Contains("shadowcopy") && cmdLower.Contains("delete"))
            {
                reason = "Ransomware Behavior: WMI Shadow Copy Deletion";
                return true;
            }
            if (cmdLower.Contains("bcdedit") && (cmdLower.Contains("recoveryenabled no") || cmdLower.Contains("bootstatuspolicy ignoreallfailures")))
            {
                reason = "Ransomware Behavior: Boot Recovery Disabled (bcdedit)";
                return true;
            }

            // 2. Gelişmiş PowerShell Obfuscation & Download Cradle & AMSI Bypass
            if (exeName.Contains("powershell") || exeName.Contains("pwsh"))
            {
                if (cmdLower.Contains("-enc ") || cmdLower.Contains("-encodedcommand ") || cmdLower.Contains("-e "))
                {
                    reason = "Obfuscation: Encoded PowerShell Command Execution";
                    return true;
                }
                if (cmdLower.Contains("downloadstring") || cmdLower.Contains("downloaddata") || cmdLower.Contains("iex(") || cmdLower.Contains("iex ("))
                {
                    reason = "Malicious Cradle: PowerShell In-Memory Payload Download & Execute";
                    return true;
                }
                if (cmdLower.Contains("amsiutil") || cmdLower.Contains("amsiinitfailed"))
                {
                    reason = "Anti-Evasion: PowerShell AMSI Tampering Attempt";
                    return true;
                }
            }

            // 3. CertUtil Dosya İndirme Kötüye Kullanımı (LOLBAS)
            if (exeName.Contains("certutil") && (cmdLower.Contains("-urlcache") || cmdLower.Contains("-split") || cmdLower.Contains("-f")))
            {
                reason = "LOLBAS Exploitation: CertUtil Remote Binary Download";
                return true;
            }

            // 4. Sistem Süreci Sahteciliği (Process Masquerading)
            if (exeName == "svchost.exe" || exeName == "lsass.exe" || exeName == "csrss.exe")
            {
                if (!PathHelper.IsSystemPath(imagePath))
                {
                    reason = $"Masquerading: Critical System Process Running from Non-System Directory ({imagePath})";
                    return true;
                }
            }

            return false;
        }

        private static string ExtractPayloadString(TraceEvent data, params string[] fieldNames)
        {
            foreach (var name in fieldNames)
            {
                var val = data.PayloadByName(name);
                if (val != null)
                {
                    string str = val.ToString() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(str)) return str;
                }
            }
            return string.Empty;
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
