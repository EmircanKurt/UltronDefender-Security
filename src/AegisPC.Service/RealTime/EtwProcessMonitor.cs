using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Services;
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
    /// Observes process start and stop events through a live ETW session. Event loss or a
    /// stopped message pump degrades this optional, post-start telemetry; it cannot block execution.
    /// Command-line heuristics are observations, not confirmed-malware findings.
    /// </summary>
    public class EtwProcessMonitor : IDisposable
    {
        private readonly ILogger<EtwProcessMonitor>? _logger;
        private readonly IProcessLineageTracker? _lineageTracker;
        private readonly IBehaviorEngine? _behaviorEngine;

        private TraceEventSession? _session;
        private Task? _processingTask;
        private CancellationTokenSource? _cts;
        private volatile bool _isRunning;
        private int _lastEventsLost;
        private readonly object _lock = new();

        public static readonly Guid KernelProcessProviderGuid = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
        public const string DefaultSessionName = "AegisPCEtwSession";
        public const string DefaultLogDirectory = @"C:\ProgramData\UltronDefender\EtwLogs";
        private const int DefaultBufferSizeMB = 32;

        private BoundedEtwLogWriter? _etlLogWriter;
        private readonly object _logLock = new();

        /// <summary>True only while the ETW message pump has not terminated; this does not imply pre-execution blocking.</summary>
        public bool IsRunning => _isRunning && _processingTask?.IsCompleted != true;

        /// <summary>Returns ETW's live lost-event count, or -1 when the active session cannot be queried.</summary>
        public int EventsLost
        {
            get
            {
                lock (_lock)
                {
                    if (_session == null) return _lastEventsLost;
                    try
                    {
                        _lastEventsLost = Math.Max(_lastEventsLost, _session.EventsLost);
                        return _lastEventsLost;
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning(ex, "Could not read ETW process event-loss counter.");
                        return -1;
                    }
                }
            }
        }

        public event Action<ProcessStartTelemetry>? ProcessStarted;
        public event Action<ProcessStopTelemetry>? ProcessStopped;

        /// <summary>Creates an optional process observer; supplied collaborators receive telemetry only after ETW starts.</summary>
        public EtwProcessMonitor(
            ILogger<EtwProcessMonitor>? logger = null,
            IProcessLineageTracker? lineageTracker = null,
            IAuditLogService? auditLogService = null,
            IBehaviorEngine? behaviorEngine = null,
            ISecurityFindingService? findingService = null)
        {
            _logger = logger;
            _lineageTracker = lineageTracker;
            _behaviorEngine = behaviorEngine;
            _ = auditLogService;
            _ = findingService;
        }

        /// <summary>Starts a live ETW session; on failure the monitor remains stopped and cleans partial resources.</summary>
        public void Start()
        {
            lock (_lock)
            {
                if (IsRunning) return;
                CleanupSession();
                _cts = new CancellationTokenSource();
                _lastEventsLost = 0;

                string sessionName = $"{DefaultSessionName}-{Environment.ProcessId}-{Guid.NewGuid():N}";

                _logger?.LogInformation("Starting ETW Process Monitor (Session: {Session}, Buffer: {Buffer}MB)...",
                    sessionName, DefaultBufferSizeMB);

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
                        _etlLogWriter = new BoundedEtwLogWriter(logFilePath);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning(ex, "Could not initialize local ETW log file at {Dir}. Continuing in-memory.", DefaultLogDirectory);
                    }

                    // A circular in-memory session has no live Source; this must remain real-time.
                    _session = new TraceEventSession(sessionName, TraceEventSessionOptions.Create)
                    {
                        BufferSizeMB = DefaultBufferSizeMB,
                        StopOnDispose = true
                    };

                    // MatchAnyKeywords: 0x10 = WINEVENT_KEYWORD_PROCESS (ProcessStart, ProcessStop, ProcessExit)
                    _session.EnableProvider(
                        KernelProcessProviderGuid,
                        TraceEventLevel.Informational,
                        matchAnyKeywords: 0x10);

                    var session = _session;
                    session.Source.Dynamic.All += OnKernelProcessEvent;

                    _isRunning = true;
                    _processingTask = Task.Factory.StartNew(
                        () =>
                        {
                            try
                            {
                                session.Source.Process();
                            }
                            catch (Exception ex)
                            {
                                if (_isRunning)
                                    _logger?.LogError(ex, "ETW process message pump failed; process telemetry is unavailable.");
                                else
                                    _logger?.LogDebug(ex, "ETW process message pump stopped during shutdown.");
                            }
                            finally
                            {
                                if (_isRunning)
                                    _logger?.LogWarning("ETW process message pump stopped unexpectedly; process telemetry is unavailable.");
                                lock (_lock)
                                {
                                    if (ReferenceEquals(_session, session)) _isRunning = false;
                                }
                            }
                        },
                        _cts.Token,
                        TaskCreationOptions.LongRunning,
                        TaskScheduler.Default);

                    _logger?.LogInformation("ETW process session configured; message pump scheduled.");
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to start ETW process session; process telemetry is unavailable.");
                    _isRunning = false;
                    CleanupSession();
                }
            }
        }

        /// <summary>Stops the ETW session and releases partial resources even if the message pump already failed.</summary>
        public void Stop()
        {
            lock (_lock)
            {
                _isRunning = false;
                CleanupSession();

                _logger?.LogInformation("ETW Process Monitor stopped.");
            }
        }

        private void CleanupSession()
        {
            _cts?.Cancel();
            if (_session != null)
            {
                try { _lastEventsLost = Math.Max(_lastEventsLost, _session.EventsLost); }
                catch (Exception ex) { _logger?.LogWarning(ex, "Could not read final ETW process loss count."); }
                try { _session.Dispose(); }
                catch (Exception ex) { _logger?.LogWarning(ex, "Could not dispose ETW process session."); }
                _session = null;
            }
            _cts?.Dispose();
            _cts = null;
            lock (_logLock)
            {
                try { _etlLogWriter?.Dispose(); }
                catch (Exception ex) { _logger?.LogWarning(ex, "Could not close ETW process log."); }
                _etlLogWriter = null;
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
                    int pid = ExtractTargetProcessId(data);
                    if (pid <= 4) return; // System idle / kernel bypass

                    string imagePath = ExtractPayloadString(data, "ImageFileName", "FileName", "ImageName");
                    string commandLine = ExtractPayloadString(data, "CommandLine", "CommandLineString");
                    int ppid = 0;

                    var ppidPayload = data.PayloadByName("ParentProcessID") ?? data.PayloadByName("ParentPID");
                    if (ppidPayload is int ppidVal) ppid = ppidVal;
                    else if (ppidPayload != null && int.TryParse(ppidPayload.ToString(), out int parsedPpid)) ppid = parsedPpid;

                    // 1. Yerel Log Dosyasına Yaz (C:\ProgramData\UltronDefender\EtwLogs\ProcessEvents.log)
                    WriteToLocalLog($"[START] {timestampUtc:yyyy-MM-dd HH:mm:ss.fff} | PID: {pid} | PPID: {ppid} | Image: {imagePath}");

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
                        catch (Exception ex)
                        {
                            _logger?.LogWarning(ex, "Could not record ETW process lineage for PID {Pid}.", pid);
                        }
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
                            ObserveBehaviorTask(_behaviorEngine.ProcessEventAsync(behaviorEvent));
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogWarning(ex, "Could not enqueue ETW process behavior for PID {Pid}.", pid);
                        }
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

                    // Heuristics alone cannot establish a malware verdict or quarantine action.
                    if (isSuspicious)
                    {
                        _logger?.LogInformation("ETW process heuristic observation: PID: {Pid}, Exe: {Exe}, Reason: {Reason}",
                            pid, imagePath, reason);
                        WriteToLocalLog($"[HEURISTIC_OBSERVATION] PID: {pid} | Reason: {reason} | Exe: {imagePath}");
                    }

                    ProcessStarted?.Invoke(telemetry);
                }
                else if (isStop)
                {
                    int pid = ExtractTargetProcessId(data);
                    if (pid <= 4) return;
                    int exitCode = 0;
                    var exitCodePayload = data.PayloadByName("ExitCode");
                    if (exitCodePayload is int ec) exitCode = ec;
                    else if (exitCodePayload is uint unsignedExitCode) exitCode = unchecked((int)unsignedExitCode);

                    WriteToLocalLog($"[EXIT]  {timestampUtc:yyyy-MM-dd HH:mm:ss.fff} | PID: {pid} | ExitCode: {exitCode}");

                    if (_lineageTracker != null)
                    {
                        try
                        {
                            _lineageTracker.MarkTerminated(pid);
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogWarning(ex, "Could not update ETW process lineage for PID {Pid}.", pid);
                        }
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

        private void ObserveBehaviorTask(Task task)
        {
            _ = task.ContinueWith(
                completed => _logger?.LogWarning(completed.Exception, "ETW process behavior processing failed."),
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted,
                TaskScheduler.Default);
        }

        private void WriteToLocalLog(string entry)
        {
            lock (_logLock)
            {
                if (_etlLogWriter == null) return;
                try
                {
                    if (_etlLogWriter.TryWrite(entry)) return;
                    _logger?.LogWarning("ETW process observation log reached its {ByteBudget} byte budget; process telemetry continues without local file logging.", BoundedEtwLogWriter.MaxLogBytes);
                    _etlLogWriter.Dispose();
                    _etlLogWriter = null;
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Could not write ETW process log; process telemetry continues without local file logging.");
                    try { _etlLogWriter?.Dispose(); }
                    catch (Exception disposeException) { _logger?.LogWarning(disposeException, "Could not close failed ETW process log."); }
                    _etlLogWriter = null;
                }
            }
        }

        /// <summary>Returns an unconfirmed command-line observation, never a standalone malware verdict.</summary>
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

        private static int ExtractTargetProcessId(TraceEvent data)
        {
            // The provider's ProcessID payload identifies the affected process; the ETW header can identify the emitter.
            var payload = data.PayloadByName("ProcessID");
            return payload switch
            {
                int pid => pid,
                uint pid when pid <= int.MaxValue => (int)pid,
                _ when int.TryParse(payload?.ToString(), out int parsed) => parsed,
                _ => 0
            };
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
