using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.RealTime
{
    public record ImageLoadTelemetry
    {
        public int ProcessId { get; init; }
        public ulong ImageBase { get; init; }
        public ulong ImageSize { get; init; }
        public string ImageLoadedPath { get; init; } = string.Empty;
        public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
        public bool IsSuspiciousSideload { get; init; }
        public string ThreatReason { get; init; } = string.Empty;
    }

    /// <summary>
    /// Observes module-load events through a live ETW session. A module path alone does not
    /// establish injection, vulnerable-driver use, or maliciousness; this is post-load telemetry.
    /// A stopped pump or lost events degrades optional coverage and is exposed to the worker.
    /// </summary>
    public class EtwImageLoadMonitor : IDisposable
    {
        private readonly ILogger<EtwImageLoadMonitor>? _logger;

        private TraceEventSession? _session;
        private Task? _processingTask;
        private CancellationTokenSource? _cts;
        private volatile bool _isRunning;
        private int _lastEventsLost;
        private readonly object _lock = new();

        public static readonly Guid KernelProcessProviderGuid = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
        public const string DefaultSessionName = "AegisPCEtwSession_ImageLoad";
        public const string DefaultLogDirectory = @"C:\ProgramData\UltronDefender\EtwLogs";
        private const int DefaultBufferSizeMB = 32;

        private BoundedEtwLogWriter? _etlLogWriter;
        private readonly object _logLock = new();

        /// <summary>True only while the ETW message pump has not terminated; this is not pre-load blocking.</summary>
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
                        _logger?.LogWarning(ex, "Could not read ETW image-load event-loss counter.");
                        return -1;
                    }
                }
            }
        }

        public event Action<ImageLoadTelemetry>? ImageLoaded;

        /// <summary>Creates an optional module observer; path heuristics never become an independent verdict.</summary>
        public EtwImageLoadMonitor(
            ILogger<EtwImageLoadMonitor>? logger = null,
            IBehaviorEngine? behaviorEngine = null,
            ISecurityFindingService? findingService = null)
        {
            _logger = logger;
            _ = behaviorEngine;
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

                _logger?.LogInformation("Starting ETW ImageLoad Monitor (Session: {Session}, Buffer: {Buffer}MB)...",
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

                        string logFilePath = Path.Combine(DefaultLogDirectory, "ImageLoadEvents.log");
                        _etlLogWriter = new BoundedEtwLogWriter(logFilePath);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning(ex, "Could not initialize local ImageLoad log file at {Dir}. Continuing in-memory.", DefaultLogDirectory);
                    }

                    // A circular in-memory session has no live Source; this must remain real-time.
                    _session = new TraceEventSession(sessionName, TraceEventSessionOptions.Create)
                    {
                        BufferSizeMB = DefaultBufferSizeMB,
                        StopOnDispose = true
                    };

                    // MatchAnyKeywords: 0x40 = WINEVENT_KEYWORD_IMAGE (ImageLoad)
                    _session.EnableProvider(
                        KernelProcessProviderGuid,
                        TraceEventLevel.Informational,
                        matchAnyKeywords: 0x40);

                    var session = _session;
                    session.Source.Dynamic.All += OnKernelImageEvent;

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
                                    _logger?.LogError(ex, "ETW image-load message pump failed; module telemetry is unavailable.");
                                else
                                    _logger?.LogDebug(ex, "ETW image-load message pump stopped during shutdown.");
                            }
                            finally
                            {
                                if (_isRunning)
                                    _logger?.LogWarning("ETW image-load message pump stopped unexpectedly; module telemetry is unavailable.");
                                lock (_lock)
                                {
                                    if (ReferenceEquals(_session, session)) _isRunning = false;
                                }
                            }
                        },
                        _cts.Token,
                        TaskCreationOptions.LongRunning,
                        TaskScheduler.Default);

                    _logger?.LogInformation("ETW image-load session configured; message pump scheduled.");
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to start ETW image-load session; module telemetry is unavailable.");
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

                _logger?.LogInformation("ETW ImageLoad Monitor stopped.");
            }
        }

        private void CleanupSession()
        {
            _cts?.Cancel();
            if (_session != null)
            {
                try { _lastEventsLost = Math.Max(_lastEventsLost, _session.EventsLost); }
                catch (Exception ex) { _logger?.LogWarning(ex, "Could not read final ETW image-load loss count."); }
                try { _session.Dispose(); }
                catch (Exception ex) { _logger?.LogWarning(ex, "Could not dispose ETW image-load session."); }
                _session = null;
            }
            _cts?.Dispose();
            _cts = null;
            lock (_logLock)
            {
                try { _etlLogWriter?.Dispose(); }
                catch (Exception ex) { _logger?.LogWarning(ex, "Could not close ETW image-load log."); }
                _etlLogWriter = null;
            }
        }

        private void OnKernelImageEvent(TraceEvent data)
        {
            if (!_isRunning) return;

            try
            {
                string eventName = data.EventName;
                if (!eventName.Contains("ImageLoad", StringComparison.OrdinalIgnoreCase) &&
                    !eventName.Contains("LoadImage", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                int pid = ExtractTargetProcessId(data);
                if (pid <= 4) return; // System bypass

                string imageLoadedPath = ExtractPayloadString(data, "FileName", "ImageFileName", "ImageName");
                if (string.IsNullOrWhiteSpace(imageLoadedPath)) return;

                DateTime timestampUtc = data.TimeStamp.Kind == DateTimeKind.Utc
                    ? data.TimeStamp
                    : data.TimeStamp.ToUniversalTime();

                ulong imageBase = 0;
                ulong imageSize = 0;

                var baseVal = data.PayloadByName("ImageBase");
                if (baseVal is ulong ulBase) imageBase = ulBase;
                else if (baseVal is long lBase) imageBase = (ulong)lBase;

                var sizeVal = data.PayloadByName("ImageSize");
                if (sizeVal is ulong ulSize) imageSize = ulSize;
                else if (sizeVal is long lSize) imageSize = (ulong)lSize;
                else if (sizeVal is int iSize) imageSize = (ulong)iSize;

                // 1. Yerel Log Dosyasına Yaz (C:\ProgramData\UltronDefender\EtwLogs\ImageLoadEvents.log)
                WriteToLocalLog($"[LOAD] {timestampUtc:yyyy-MM-dd HH:mm:ss.fff} | PID: {pid} | Base: 0x{imageBase:X} | Size: {imageSize} | Path: {imageLoadedPath}");

                // 2. DLL Side-loading ve Enjeksiyon Analizi
                bool isSuspicious = CheckSuspiciousImageLoad(pid, imageLoadedPath, out string reason);

                var telemetry = new ImageLoadTelemetry
                {
                    ProcessId = pid,
                    ImageBase = imageBase,
                    ImageSize = imageSize,
                    ImageLoadedPath = imageLoadedPath,
                    TimestampUtc = timestampUtc,
                    IsSuspiciousSideload = isSuspicious,
                    ThreatReason = reason
                };

                // A path-only heuristic is not evidence of injection or a malicious driver.
                if (isSuspicious)
                {
                    _logger?.LogInformation("ETW image-load heuristic observation: PID: {Pid}, Module: {Module}, Reason: {Reason}",
                        pid, imageLoadedPath, reason);

                    WriteToLocalLog($"[HEURISTIC_OBSERVATION] PID: {pid} | Reason: {reason} | Module: {imageLoadedPath}");
                }

                ImageLoaded?.Invoke(telemetry);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error processing ETW ImageLoad event.");
            }
        }

        private void WriteToLocalLog(string entry)
        {
            lock (_logLock)
            {
                if (_etlLogWriter == null) return;
                try
                {
                    if (_etlLogWriter.TryWrite(entry)) return;
                    _logger?.LogWarning("ETW image-load observation log reached its {ByteBudget} byte budget; module telemetry continues without local file logging.", BoundedEtwLogWriter.MaxLogBytes);
                    _etlLogWriter.Dispose();
                    _etlLogWriter = null;
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Could not write ETW image-load log; module telemetry continues without local file logging.");
                    try { _etlLogWriter?.Dispose(); }
                    catch (Exception disposeException) { _logger?.LogWarning(disposeException, "Could not close failed ETW image-load log."); }
                    _etlLogWriter = null;
                }
            }
        }

        /// <summary>Returns an unconfirmed path/name observation, never proof of injection or a malicious driver.</summary>
        public static bool CheckSuspiciousImageLoad(int pid, string modulePath, out string reason)
        {
            reason = string.Empty;
            if (string.IsNullOrWhiteSpace(modulePath)) return false;

            string moduleName = Path.GetFileName(modulePath).ToLowerInvariant();
            string moduleDir = Path.GetDirectoryName(modulePath)?.ToLowerInvariant() ?? string.Empty;

            // 1. Temp, AppData veya Downloads altından DLL yükleme tespiti
            bool isTempOrAppData = moduleDir.Contains(@"\temp") ||
                                   moduleDir.Contains(@"\appdata\local\temp") ||
                                   moduleDir.Contains(@"\downloads");

            // Bilinen yaygın DLL side-loading kurbanı/hedefi DLL isimleri veya doğrudan Temp/AppData'dan yüklenen şüpheli DLL'ler
            bool isCommonSideloadTarget = moduleName is "version.dll" or "cryptbase.dll" or "userenv.dll" or
                                                      "uxtheme.dll" or "dbghelp.dll" or "msasn1.dll" or "propsys.dll";

            if (isTempOrAppData && (isCommonSideloadTarget || moduleName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
            {
                reason = $"DLL Side-Loading Suspect: Module '{moduleName}' loaded from user writable location (Temp: {modulePath})";
                return true;
            }

            // 2. Doğrudan .sys (Kernel Sürücü) dosyasının kullanıcı alanından veya bilinen istismar sürücülerinden (BYOVD Rootkit) yüklenmesi
            bool isKnownByovdDriver = moduleName is "rtcore64.sys" or "mhyprot2.sys" or "gdrv.sys" or "dbutil_2_3.sys" or "procexp.sys";
            bool isNonStandardDriverDir = !moduleDir.Contains(@"\windows\system32\drivers") && !moduleDir.Contains(@"\systemroot\system32\drivers");

            if (moduleName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) && (isTempOrAppData || isKnownByovdDriver || isNonStandardDriverDir))
            {
                reason = $"BYOVD / Rootkit Indicator: Vulnerable or non-standard kernel driver '{moduleName}' loaded ({modulePath})";
                return true;
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
