using System;
using System.Collections.Generic;
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
    /// Microsoft-Windows-Kernel-Process ETW Sağlayıcısı üzerinden gerçek zamanlı
    /// DLL, Çalıştırılabilir Modül ve Kernel Sürücüsü (.sys) yükleme telemetri motoru (ImageLoad).
    /// DLL Side-Loading, DLL Injection ve BYOVD (Bring Your Own Vulnerable Driver) tespiti yapar.
    /// 256 MB döngüsel bellek (circular buffer), yerel ETL/log kaydı ve BehaviorEngine/SecurityFinding entegrasyonu içerir.
    /// </summary>
    public class EtwImageLoadMonitor : IDisposable
    {
        private readonly ILogger<EtwImageLoadMonitor>? _logger;
        private readonly IBehaviorEngine? _behaviorEngine;
        private readonly ISecurityFindingService? _findingService;

        private TraceEventSession? _session;
        private Task? _processingTask;
        private CancellationTokenSource? _cts;
        private bool _isRunning;
        private readonly object _lock = new();

        public static readonly Guid KernelProcessProviderGuid = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
        public const string DefaultSessionName = "AegisPCEtwSession_ImageLoad";
        public const string DefaultLogDirectory = @"C:\ProgramData\UltronDefender\EtwLogs";
        private const int DefaultBufferSizeMB = 256;

        private StreamWriter? _etlLogWriter;
        private readonly object _logLock = new();

        public bool IsRunning => _isRunning;

        public event Action<ImageLoadTelemetry>? ImageLoaded;

        public EtwImageLoadMonitor(
            ILogger<EtwImageLoadMonitor>? logger = null,
            IBehaviorEngine? behaviorEngine = null,
            ISecurityFindingService? findingService = null)
        {
            _logger = logger;
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

                _logger?.LogInformation("Starting ETW ImageLoad Monitor (Session: {Session}, Buffer: {Buffer}MB)...",
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

                        string logFilePath = Path.Combine(DefaultLogDirectory, "ImageLoadEvents.log");
                        var fs = new FileStream(logFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                        _etlLogWriter = new StreamWriter(fs, Encoding.UTF8) { AutoFlush = true };
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning(ex, "Could not initialize local ImageLoad log file at {Dir}. Continuing in-memory.", DefaultLogDirectory);
                    }

                    // 2. Önceki artık oturum varsa temizle
                    try
                    {
                        var existingSession = TraceEventSession.GetActiveSession(DefaultSessionName);
                        existingSession?.Dispose();
                    }
                    catch { }

                    // 3. 256 MB Döngüsel Bellek ile ETW Oturumu Başlat
                    _session = new TraceEventSession(DefaultSessionName, TraceEventSessionOptions.Create)
                    {
                        BufferSizeMB = DefaultBufferSizeMB,
                        CircularBufferMB = DefaultBufferSizeMB,
                        StopOnDispose = true
                    };

                    // MatchAnyKeywords: 0x40 = WINEVENT_KEYWORD_IMAGE (ImageLoad)
                    _session.EnableProvider(
                        KernelProcessProviderGuid,
                        TraceEventLevel.Informational,
                        matchAnyKeywords: 0x40);

                    // 4. Olay Dinleyicisi
                    _session.Source.Dynamic.All += OnKernelImageEvent;

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
                                _logger?.LogDebug(ex, "ETW ImageLoad message pump terminated.");
                            }
                        },
                        _cts.Token,
                        TaskCreationOptions.LongRunning,
                        TaskScheduler.Default);

                    _logger?.LogInformation("ETW ImageLoad Monitor session active and listening.");
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to start ETW ImageLoad Monitor session (non-admin rights or session limit). Progressive fallback active.");
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
                    _logger?.LogTrace(ex, "Error stopping ETW ImageLoad Monitor session.");
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

                _logger?.LogInformation("ETW ImageLoad Monitor stopped.");
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

                int pid = data.ProcessID;
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

                // 3. Davranış Motoruna Besle (BehaviorEngine.ProcessEventAsync)
                if (_behaviorEngine != null)
                {
                    try
                    {
                        var behaviorEvent = new BehaviorEvent
                        {
                            EventType = isSuspicious ? BehaviorEventType.ProcessInjection : BehaviorEventType.ProcessSpawn,
                            ProcessId = pid,
                            ProcessName = Path.GetFileName(imageLoadedPath),
                            ExecutablePath = imageLoadedPath,
                            Timestamp = timestampUtc,
                            Details = $"Module loaded: {imageLoadedPath} (Base: 0x{imageBase:X}, Size: {imageSize} bytes)"
                        };
                        _ = _behaviorEngine.ProcessEventAsync(behaviorEvent);
                    }
                    catch { }
                }

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

                // 4. Şüpheli Modül/Enjeksiyon Durumunda SecurityFinding Oluştur
                if (isSuspicious)
                {
                    _logger?.LogWarning("SECURITY ALERT: Suspicious DLL/Image Load! PID: {Pid}, Module: {Module}, Reason: {Reason}",
                        pid, imageLoadedPath, reason);

                    WriteToLocalLog($"[SECURITY_ALERT] PID: {pid} | Threat: {reason} | Module: {imageLoadedPath}");

                    if (_findingService != null)
                    {
                        var finding = new SecurityFinding
                        {
                            Id = Guid.NewGuid(),
                            ObjectPath = imageLoadedPath,
                            ObjectName = Path.GetFileName(imageLoadedPath),
                            RiskLevel = RiskLevel.HighRisk,
                            RiskScore = 90,
                            Category = FindingCategory.SuspiciousLocation,
                            Title = $"DLL Side-Loading / Injection: {reason}",
                            Description = $"PID {pid} loaded suspicious module from unprivileged directory: {imageLoadedPath}",
                            RiskReasons = new List<string> { reason, $"Module Base: 0x{imageBase:X}", $"Module Size: {imageSize} bytes" },
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

                ImageLoaded?.Invoke(telemetry);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error processing ETW ImageLoad event.");
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

        public void Dispose()
        {
            Stop();
        }
    }
}
