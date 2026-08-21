using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    public class NormalizedFileEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public string CorrelationId { get; set; } = Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public RealTimeEventType EventType { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public string NormalizedPath { get; set; } = string.Empty;
        public string? OldFilePath { get; set; }
        public long FileSize { get; set; }
        public string Extension { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string Source { get; set; } = "FileSystemWatcher";
    }

    public class RealTimeActivityEvent
    {
        public string CorrelationId { get; set; } = Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string Stage { get; set; } = string.Empty; // "EVENT_CAPTURED", "STABILITY_CHECK", "SCAN_STARTED", "ANALYSIS_COMPLETED", "VERDICT", "ACTION_APPLIED"
        public string Message { get; set; } = string.Empty;
        public int RiskScore { get; set; }
        public string Verdict { get; set; } = "Clean";
        public string Action { get; set; } = "Allow";
        public double TimeToDetectMs { get; set; }
        public double TimeToActionMs { get; set; }
        public string Severity { get; set; } = "Info"; // "Info", "Warning", "Danger", "Success"
    }

    public class RealTimeVerdictResult
    {
        public RealTimeVerdict Verdict { get; set; }
        public double Confidence { get; set; }
        public int RiskScore { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public string ThreatTitle { get; set; } = string.Empty;
        public string ThreatDescription { get; set; } = string.Empty;
        public List<string> Evidences { get; set; } = new();
        public RealTimePolicyAction RecommendedPolicy { get; set; }
        public string SHA256 { get; set; } = string.Empty;

        // Telemetry Timestamps (Time-to-Detect & Time-to-Action)
        public DateTime EventTime { get; set; } = DateTime.UtcNow;
        public DateTime ScanStartTime { get; set; } = DateTime.UtcNow;
        public DateTime ScanEndTime { get; set; } = DateTime.UtcNow;
        public DateTime VerdictTime { get; set; } = DateTime.UtcNow;
        public DateTime ActionTime { get; set; } = DateTime.UtcNow;

        public double TimeToDetectMs => (ScanEndTime - EventTime).TotalMilliseconds > 0 
            ? (ScanEndTime - EventTime).TotalMilliseconds 
            : Math.Max(0.1, (ScanEndTime - ScanStartTime).TotalMilliseconds);

        public double TimeToActionMs => (ActionTime - EventTime).TotalMilliseconds > 0 
            ? (ActionTime - EventTime).TotalMilliseconds 
            : Math.Max(0.1, (ActionTime - ScanStartTime).TotalMilliseconds);
    }

    public interface IRealTimeProtectionEngine
    {
        void Start();
        void Stop();
        bool IsRunning { get; }
        IReadOnlyList<string> WatchedLocations { get; }
        void AddWatchDirectory(string path);
        event Action<SecurityFinding>? OnThreatDetected;
        event Action<SecurityIncident>? OnIncidentCreated;
        event Action<string, string, string>? OnNotificationRaised; // title, message, type (Success, Warning, Danger)
        event Action<RealTimeActivityEvent>? OnActivityLogged;
        event Action<bool, string>? OnProtectionHealthChanged;
        Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Gerçek zamanlı, çok aşamalı (Progressive Analysis), olay kararlılığı (Stability Check) doğrulamalı,
    /// sıfır sahte veri (Zero-Mock) içeren Windows Endpoint Real-Time Protection Motoru.
    /// </summary>
    public class RealTimeProtectionEngine : IRealTimeProtectionEngine, IDisposable
    {
        private readonly IFileScanner _fileScanner;
        private readonly IHashService _hashService;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IRiskScoringEngine _riskScoringEngine;
        private readonly IQuarantineService _quarantineService;
        private readonly ISecurityFindingService _findingService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger<RealTimeProtectionEngine>? _logger;

        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly List<string> _watchedLocationsList = new();
        private readonly Channel<NormalizedFileEvent> _eventChannel;
        private readonly ConcurrentDictionary<string, (string hash, RealTimeVerdict verdict, RealTimePolicyAction policy, int riskScore, RiskLevel riskLevel, DateTime cachedAt)> _verdictCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTime> _recentlyProcessed = new(StringComparer.OrdinalIgnoreCase);
        private CancellationTokenSource? _engineCts;
        private Task? _processingTask;
        private bool _isRunning;
        private readonly object _lock = new();
        private Timer? _cacheCleanupTimer;

        private static readonly string[] DangerousExtensions = new[]
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jar", ".iso", ".zip", ".rar", ".7z", ".vbe", ".wsf", ".cpl", ".msi", ".com", ".pif"
        };

        public bool IsRunning => _isRunning;
        public IReadOnlyList<string> WatchedLocations
        {
            get
            {
                lock (_lock) { return _watchedLocationsList.ToArray(); }
            }
        }

        public event Action<SecurityFinding>? OnThreatDetected;
        public event Action<SecurityIncident>? OnIncidentCreated;
        public event Action<string, string, string>? OnNotificationRaised;
        public event Action<RealTimeActivityEvent>? OnActivityLogged;
        public event Action<bool, string>? OnProtectionHealthChanged;

        public RealTimeProtectionEngine(
            IFileScanner fileScanner,
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IQuarantineService quarantineService,
            ISecurityFindingService findingService,
            IAuditLogService? auditLogService = null,
            ILogger<RealTimeProtectionEngine>? logger = null)
        {
            _fileScanner = fileScanner;
            _hashService = hashService;
            _signatureVerifier = signatureVerifier;
            _riskScoringEngine = riskScoringEngine;
            _quarantineService = quarantineService;
            _findingService = findingService;
            _auditLogService = auditLogService;
            _logger = logger;

            _eventChannel = Channel.CreateBounded<NormalizedFileEvent>(new BoundedChannelOptions(5000)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            });
        }

        public void Start() => Start(watchDefaultLocations: true);

        public void Start(bool watchDefaultLocations = true)
        {
            lock (_lock)
            {
                if (_isRunning) return;
                _isRunning = true;
                _engineCts = new CancellationTokenSource();

                // 1. Setup Watchers on Critical Directories
                if (watchDefaultLocations)
                {
                    SetupFileSystemWatchers();
                }

                foreach (var w in _watchers)
                {
                    try { w.EnableRaisingEvents = true; } catch { }
                }

                // 2. Start Background Event Processing Worker
                _processingTask = Task.Run(() => ProcessEventLoopAsync(_engineCts.Token));

                _cacheCleanupTimer = new Timer(CleanupCache, null, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));

                _logger?.LogInformation("Ultron Defender Real-Time Protection Engine started successfully.");
                OnProtectionHealthChanged?.Invoke(true, "Sağlıklı - Tüm dizinler izleniyor");
            }
        }

        private void CleanupCache(object? state)
        {
            var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(30);
            var expiredKeys = _verdictCache.Where(kvp => kvp.Value.cachedAt < cutoff).Select(kvp => kvp.Key).ToList();
            foreach (var key in expiredKeys)
            {
                _verdictCache.TryRemove(key, out _);
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning) return;
                _isRunning = false;

                foreach (var w in _watchers)
                {
                    try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
                }
                _watchers.Clear();
                _watchedLocationsList.Clear();

                _engineCts?.Cancel();
                _engineCts?.Dispose();
                _engineCts = null;

                _cacheCleanupTimer?.Dispose();
                _cacheCleanupTimer = null;

                _logger?.LogInformation("Ultron Defender Real-Time Protection Engine stopped.");
                OnProtectionHealthChanged?.Invoke(false, "Durduruldu");
            }
        }

        private void SetupFileSystemWatchers()
        {
            var pathsToWatch = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // User Downloads
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var downloads = Path.Combine(userProfile, "Downloads");
            if (Directory.Exists(downloads)) pathsToWatch.Add(downloads);

            // User Desktop
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (Directory.Exists(desktop)) pathsToWatch.Add(desktop);

            // User Documents
            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (Directory.Exists(documents)) pathsToWatch.Add(documents);

            // Temp directories
            var localTemp = Path.GetTempPath();
            if (Directory.Exists(localTemp)) pathsToWatch.Add(localTemp);

            var winTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
            if (Directory.Exists(winTemp)) pathsToWatch.Add(winTemp);

            // User AppData Local & Roaming
            var appDataLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (Directory.Exists(appDataLocal)) pathsToWatch.Add(appDataLocal);

            var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (Directory.Exists(appDataRoaming)) pathsToWatch.Add(appDataRoaming);

            // ProgramData (CommonApplicationData)
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (Directory.Exists(programData)) pathsToWatch.Add(programData);

            // Startup folders
            var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (Directory.Exists(userStartup)) pathsToWatch.Add(userStartup);

            var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            if (Directory.Exists(commonStartup)) pathsToWatch.Add(commonStartup);

            // Removable / USB Drives
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.DriveType == DriveType.Removable && drive.IsReady)
                    {
                        pathsToWatch.Add(drive.RootDirectory.FullName);
                    }
                }
            }
            catch { }

            foreach (var path in pathsToWatch)
            {
                AttachWatcher(path);
            }
        }

        public void AddWatchDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return;

            lock (_lock)
            {
                AttachWatcher(path);
            }
        }

        private void AttachWatcher(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return;

            try
            {
                if (_watchedLocationsList.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    return;
                }

                var watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                    IncludeSubdirectories = true,
                    InternalBufferSize = 65536,
                    EnableRaisingEvents = _isRunning
                };

                watcher.Created += (s, e) => EnqueueEvent(RealTimeEventType.Created, e.FullPath);
                watcher.Changed += (s, e) => EnqueueEvent(RealTimeEventType.Modified, e.FullPath);
                watcher.Renamed += (s, e) => EnqueueEvent(RealTimeEventType.Renamed, e.FullPath, e.OldFullPath);
                watcher.Error += (s, e) =>
                {
                    _logger?.LogWarning(e.GetException(), "FileSystemWatcher buffer overflow or I/O error on dynamic path {Path}.", path);
                    OnProtectionHealthChanged?.Invoke(false, $"Dinamik Yol Arabellek Taşması: {path}");
                    try
                    {
                        watcher.EnableRaisingEvents = false;
                        watcher.EnableRaisingEvents = true;
                        OnProtectionHealthChanged?.Invoke(true, "Sağlıklı");
                    }
                    catch { }
                };

                _watchers.Add(watcher);
                _watchedLocationsList.Add(path);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Could not initialize real-time watcher for {Path}", path);
            }
        }

        private void EnqueueEvent(RealTimeEventType type, string path, string? oldPath = null)
        {
            if (string.IsNullOrWhiteSpace(path)) return;

            var ext = Path.GetExtension(path).ToLowerInvariant();
            if (!DangerousExtensions.Contains(ext)) return;

            var normalizedEvent = new NormalizedFileEvent
            {
                EventType = type,
                FilePath = path,
                NormalizedPath = Path.GetFullPath(path),
                OldFilePath = oldPath,
                Extension = ext,
                Timestamp = DateTime.UtcNow
            };

            _eventChannel.Writer.TryWrite(normalizedEvent);
        }

        private async Task ProcessEventLoopAsync(CancellationToken ct)
        {
            var reader = _eventChannel.Reader;
            while (!ct.IsCancellationRequested && await reader.WaitToReadAsync(ct))
            {
                while (reader.TryRead(out var evt))
                {
                    if (ct.IsCancellationRequested) break;

                    try
                    {
                        var fileName = Path.GetFileName(evt.NormalizedPath);

                        // Stage 1: Event Captured Telemetry
                        OnActivityLogged?.Invoke(new RealTimeActivityEvent
                        {
                            CorrelationId = evt.CorrelationId,
                            FileName = fileName,
                            FilePath = evt.NormalizedPath,
                            Stage = "FILE_DETECTED",
                            Message = $"Dosya hareketi algılandı ({evt.EventType})",
                            Severity = "Info",
                            Timestamp = DateTime.Now
                        });

                        // Stage 2: Wait for file write stability (file download or write completion)
                        OnActivityLogged?.Invoke(new RealTimeActivityEvent
                        {
                            CorrelationId = evt.CorrelationId,
                            FileName = fileName,
                            FilePath = evt.NormalizedPath,
                            Stage = "STABILITY_CHECK",
                            Message = "Dosya stabilite ve yazma kilidi kontrol ediliyor...",
                            Severity = "Info",
                            Timestamp = DateTime.Now
                        });

                        bool isStable = await WaitForFileStabilityAsync(evt.NormalizedPath, ct);
                        if (!isStable || !File.Exists(evt.NormalizedPath)) continue;

                        // Stage 3: Progressive Instant Arrival Inspection
                        OnActivityLogged?.Invoke(new RealTimeActivityEvent
                        {
                            CorrelationId = evt.CorrelationId,
                            FileName = fileName,
                            FilePath = evt.NormalizedPath,
                            Stage = "SCAN_STARTED",
                            Message = "Progresif güvenlik taraması başlatıldı (Hash, İmza, PE, Sezgiseller)...",
                            Severity = "Info",
                            Timestamp = DateTime.Now
                        });

                        var verdict = await InspectFileAsync(evt.NormalizedPath, ct);
                        verdict.EventTime = evt.Timestamp;

                        // Stage 4: Verdict Telemetry
                        OnActivityLogged?.Invoke(new RealTimeActivityEvent
                        {
                            CorrelationId = evt.CorrelationId,
                            FileName = fileName,
                            FilePath = evt.NormalizedPath,
                            Stage = "VERDICT",
                            RiskScore = verdict.RiskScore,
                            Verdict = verdict.Verdict.ToString(),
                            TimeToDetectMs = verdict.TimeToDetectMs,
                            Message = $"Risk Skoru: {verdict.RiskScore}/100 ({verdict.Verdict}) - TTD: {verdict.TimeToDetectMs:F1}ms",
                            Severity = verdict.RiskScore >= 70 ? "Danger" : (verdict.RiskScore >= 40 ? "Warning" : "Success"),
                            Timestamp = DateTime.Now
                        });

                        // Stage 5: Policy Enforcement
                        if (verdict.RecommendedPolicy == RealTimePolicyAction.BlockAndQuarantine)
                        {
                            await EnforceQuarantineAsync(evt, verdict, ct);
                            verdict.ActionTime = DateTime.UtcNow;

                            OnActivityLogged?.Invoke(new RealTimeActivityEvent
                            {
                                CorrelationId = evt.CorrelationId,
                                FileName = fileName,
                                FilePath = evt.NormalizedPath,
                                Stage = "ACTION_APPLIED",
                                Action = "QUARANTINED",
                                RiskScore = verdict.RiskScore,
                                Verdict = verdict.Verdict.ToString(),
                                TimeToActionMs = verdict.TimeToActionMs,
                                Message = $"Müdahale: Karantinaya Alındı (TTA: {verdict.TimeToActionMs:F1}ms)",
                                Severity = "Danger",
                                Timestamp = DateTime.Now
                            });
                        }
                        else if (verdict.RecommendedPolicy == RealTimePolicyAction.Warn)
                        {
                            await EnforceWarningAsync(evt, verdict, ct);
                            verdict.ActionTime = DateTime.UtcNow;

                            OnActivityLogged?.Invoke(new RealTimeActivityEvent
                            {
                                CorrelationId = evt.CorrelationId,
                                FileName = fileName,
                                FilePath = evt.NormalizedPath,
                                Stage = "ACTION_APPLIED",
                                Action = "WARN",
                                RiskScore = verdict.RiskScore,
                                Verdict = verdict.Verdict.ToString(),
                                TimeToActionMs = verdict.TimeToActionMs,
                                Message = $"Müdahale: Kullanıcı Uyarıldı, Dosya Korundu (TTA: {verdict.TimeToActionMs:F1}ms)",
                                Severity = "Warning",
                                Timestamp = DateTime.Now
                            });
                        }
                        else
                        {
                            // Policy is Allow / Unknown - LOG ONLY, NEVER DELETE UNKNOWN!
                            verdict.ActionTime = DateTime.UtcNow;
                            _logger?.LogInformation("Instant File Arrival: '{Path}' evaluated as {Verdict} (TimeToDetect: {Ttd:F1}ms). Allowed.", evt.NormalizedPath, verdict.Verdict, verdict.TimeToDetectMs);

                            OnActivityLogged?.Invoke(new RealTimeActivityEvent
                            {
                                CorrelationId = evt.CorrelationId,
                                FileName = fileName,
                                FilePath = evt.NormalizedPath,
                                Stage = "ACTION_APPLIED",
                                Action = "ALLOWED",
                                RiskScore = verdict.RiskScore,
                                Verdict = verdict.Verdict.ToString(),
                                TimeToActionMs = verdict.TimeToActionMs,
                                Message = $"Müdahale: İzin Verildi (TTA: {verdict.TimeToActionMs:F1}ms)",
                                Severity = "Success",
                                Timestamp = DateTime.Now
                            });
                        }
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "Error processing normalized real-time event for {Path}", evt.NormalizedPath);
                    }
                }
            }
        }

        /// <summary>
        /// Dosya yazımı devam ederken (örneğin web tarayıcısı .exe indirirken) dosyanın tamamlanmasını bekler.
        /// </summary>
        private async Task<bool> WaitForFileStabilityAsync(string filePath, CancellationToken ct)
        {
            const int maxAttempts = 15;
            const int delayMs = 40;

            for (int i = 0; i < maxAttempts; i++)
            {
                if (ct.IsCancellationRequested) return false;
                if (!File.Exists(filePath)) return false;

                try
                {
                    var fileInfo = new FileInfo(filePath);
                    long currentSize = fileInfo.Length;

                    // Try opening for read access with shared read/write/delete
                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        if (fs.Length > 0 && fs.Length == currentSize)
                        {
                            return true; // File is stable and immediately accessible
                        }
                    }
                }
                catch (IOException)
                {
                    // File is still being written to by another process
                }

                await Task.Delay(delayMs, ct);
            }

            return File.Exists(filePath);
        }

        public async Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default)
        {
            var scanStart = DateTime.UtcNow;
            var result = new RealTimeVerdictResult
            {
                Verdict = RealTimeVerdict.Clean,
                RecommendedPolicy = RealTimePolicyAction.Allow,
                RiskScore = 0,
                RiskLevel = RiskLevel.Clean,
                ScanStartTime = scanStart
            };

            if (!File.Exists(filePath))
            {
                result.ScanEndTime = DateTime.UtcNow;
                result.VerdictTime = DateTime.UtcNow;
                return result;
            }

            try
            {
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length == 0)
                {
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                var ext = fileInfo.Extension.ToLowerInvariant();

                // STAGE 1: Fast Hash & Signature Database Check
                var sha256 = await _hashService.ComputeSha256Async(filePath, ct);
                result.SHA256 = sha256;

                const string emptySha = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";

                // Cache Lookup (Composite key: SHA256 + FileName to avoid cross-heuristic cache contamination)
                var cacheKey = $"{sha256}::{fileInfo.Name.ToLowerInvariant()}";
                if (!string.IsNullOrEmpty(sha256) && !sha256.Equals(emptySha, StringComparison.OrdinalIgnoreCase) && _verdictCache.TryGetValue(cacheKey, out var cached) && (DateTime.UtcNow - cached.cachedAt).TotalMinutes < 30)
                {
                    result.Verdict = cached.verdict;
                    result.RecommendedPolicy = cached.policy;
                    result.RiskScore = cached.riskScore;
                    result.RiskLevel = cached.riskLevel;
                    if (result.Verdict == RealTimeVerdict.ConfirmedMalicious)
                    {
                        result.ThreatTitle = $"Zararlı Dosya (Önbellek): {fileInfo.Name}";
                    }
                    else if (result.Verdict == RealTimeVerdict.Suspicious)
                    {
                        result.ThreatTitle = $"Şüpheli Dosya (Önbellek): {fileInfo.Name}";
                    }
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // Check Known Malware Signatures (EICAR, Ransomware, Droppers, Keyloggers)
                var hashMatch = !string.IsNullOrEmpty(sha256) ? MalwareSignatureDatabase.CheckHash(sha256) : new MalwareSignatureMatch();
                if (hashMatch.IsMatched)
                {
                    result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.99;
                    result.RiskScore = hashMatch.SeverityScore;
                    result.RiskLevel = RiskLevel.ConfirmedMalicious;
                    result.ThreatTitle = $"🚨 Zararlı Yazılım: {hashMatch.ThreatName}";
                    result.ThreatDescription = $"Dosya bilinen tehdit veritabanındaki '{hashMatch.ThreatName}' imzasıyla eşleşti.";
                    result.Evidences.Add($"İmza: {hashMatch.ThreatName} ({hashMatch.ThreatCategory})");
                    result.Evidences.Add($"Tespit Metodu: {hashMatch.DetectionMethod}");

                    if (!string.IsNullOrEmpty(sha256)) _verdictCache[cacheKey] = (sha256, result.Verdict, result.RecommendedPolicy, result.RiskScore, result.RiskLevel, DateTime.UtcNow);
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // Check Pattern & YARA-like Rules (EICAR, Keyloggers, Mimikatz, ShadowCopy Deletion)
                var patternMatch = await MalwareSignatureDatabase.CheckFileContentPatternsAsync(filePath, ct);
                if (patternMatch.IsMatched)
                {
                    result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.95;
                    result.RiskScore = patternMatch.SeverityScore;
                    result.RiskLevel = RiskLevel.ConfirmedMalicious;
                    result.ThreatTitle = $"🚨 Şüpheli Kod Deseni: {patternMatch.ThreatName}";
                    result.ThreatDescription = $"Dosya içeriğinde tehlikeli dropper, exploit veya keylogger kodu tespit edildi.";
                    result.Evidences.Add($"Desen: {patternMatch.ThreatName}");
                    result.Evidences.Add($"Metod: {patternMatch.DetectionMethod}");

                    if (!string.IsNullOrEmpty(sha256)) _verdictCache[cacheKey] = (sha256, result.Verdict, result.RecommendedPolicy, result.RiskScore, result.RiskLevel, DateTime.UtcNow);
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // STAGE 2: Digital Signature & Trusted Publisher
                var sigInfo = await _signatureVerifier.VerifySignatureAsync(filePath, ct);
                if (sigInfo.IsValid && sigInfo.Publisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true && PathHelper.IsKnownSafePath(filePath))
                {
                    if (!string.IsNullOrEmpty(sha256)) _verdictCache[cacheKey] = (sha256, RealTimeVerdict.Clean, RealTimePolicyAction.Allow, 0, RiskLevel.Clean, DateTime.UtcNow);
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // STAGE 3: Entropy & PE Heuristics
                var entropy = await EntropyCalculator.CalculateEntropyAsync(filePath, ct);
                bool isExe = DangerousExtensions.Contains(ext);
                var peAnalysis = isExe ? PeAnalyzer.Analyze(filePath) : new PeAnalysisResult();

                var fileAnalysis = new FileAnalysisResult
                {
                    FilePath = filePath,
                    FileName = fileInfo.Name,
                    SHA256 = sha256,
                    FileSize = fileInfo.Length,
                    CreatedAt = fileInfo.CreationTimeUtc,
                    ModifiedAt = fileInfo.LastWriteTimeUtc,
                    IsSigned = sigInfo.IsSigned,
                    SignaturePublisher = sigInfo.Publisher,
                    SignatureValid = sigInfo.IsValid,
                    IsExecutable = isExe,
                    ExecutableType = peAnalysis.ExecutableType,
                    Entropy = entropy,
                    IsKnownLocation = PathHelper.IsKnownSafePath(filePath)
                };

                var (score, riskLevel, reasons) = await _riskScoringEngine.CalculateRiskScoreAsync(fileAnalysis, ct);
                result.RiskScore = score;
                result.RiskLevel = riskLevel;
                result.Evidences.AddRange(reasons);

                // POLICY MATRIX:
                // 1. Confirmed Malicious / Score >= 85 (High Confidence) -> BlockAndQuarantine
                // 2. High Risk / Score >= 70 (Medium Confidence) -> BlockAndQuarantine
                // 3. Suspicious / Score >= 40 (Low Confidence) -> Warn (ALLOW + LOG + USER ALERT, NEVER DELETE)
                // 4. Clean / Unknown -> Allow (NEVER DELETE UNKNOWN)
                if (riskLevel >= RiskLevel.ConfirmedMalicious || score >= 85)
                {
                    result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.95;
                    result.ThreatTitle = $"🚨 Zararlı Yazılım: {fileInfo.Name}";
                    result.ThreatDescription = string.Join(" ", reasons.Take(2));
                }
                else if (riskLevel >= RiskLevel.HighRisk || score >= 70)
                {
                    result.Verdict = RealTimeVerdict.Suspicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.80;
                    result.ThreatTitle = $"⚠️ Yüksek Riskli Dosya: {fileInfo.Name}";
                    result.ThreatDescription = string.Join(" ", reasons.Take(2));
                }
                else if (score >= 40)
                {
                    result.Verdict = RealTimeVerdict.Suspicious;
                    result.RecommendedPolicy = RealTimePolicyAction.Warn;
                    result.Confidence = 0.50;
                    result.ThreatTitle = $"⚠️ Şüpheli Dosya Uyarısı: {fileInfo.Name}";
                    result.ThreatDescription = string.Join(" ", reasons.Take(2));
                }
                else
                {
                    result.Verdict = RealTimeVerdict.Clean;
                    result.RecommendedPolicy = RealTimePolicyAction.Allow;
                    result.Confidence = 0.90;
                }

                if (!string.IsNullOrEmpty(sha256) && !sha256.Equals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", StringComparison.OrdinalIgnoreCase))
                {
                    _verdictCache[cacheKey] = (sha256, result.Verdict, result.RecommendedPolicy, result.RiskScore, result.RiskLevel, DateTime.UtcNow);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Inspection failed for {Path}", filePath);
            }
            finally
            {
                result.ScanEndTime = DateTime.UtcNow;
                result.VerdictTime = DateTime.UtcNow;
            }

            return result;
        }

        private async Task EnforceWarningAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct)
        {
            try
            {
                var fileInfo = new FileInfo(evt.NormalizedPath);
                var finding = new SecurityFinding
                {
                    ObjectPath = evt.NormalizedPath,
                    ObjectName = fileInfo.Name,
                    SHA256 = verdict.SHA256,
                    RiskLevel = verdict.RiskLevel,
                    RiskScore = verdict.RiskScore,
                    Category = FindingCategory.MalwareSuspicion,
                    Title = verdict.ThreatTitle,
                    Description = verdict.ThreatDescription,
                    RiskReasons = verdict.Evidences,
                    ConfidenceLevel = ConfidenceLevel.Medium,
                    FirstObserved = DateTime.UtcNow,
                    LastObserved = DateTime.UtcNow,
                    Status = FindingStatus.Active
                };

                await _findingService.AddFindingAsync(finding, ct);
                OnThreatDetected?.Invoke(finding);

                // Master UX Policy: Do not spam user toasts for low-confidence warnings (Score < 70).
                // Log silently to Security Center and Audit Log instead.
                if (verdict.RiskScore >= 70)
                {
                    string toastTitle = "⚠️ Yüksek Riskli Dosya Algılandı";
                    string toastMsg = $"'{fileInfo.Name}' şüpheli davranış deseni sergiliyor (Skor: {verdict.RiskScore}/100).";
                    OnNotificationRaised?.Invoke(toastTitle, toastMsg, "Warning");
                }

                if (_auditLogService != null)
                {
                    await _auditLogService.LogActionAsync(
                        AuditAction.ScanCompleted,
                        "InstantArrivalProtection",
                        fileInfo.Name,
                        evt.NormalizedPath,
                        $"Şüpheli dosya uyarısı (Skor: {verdict.RiskScore}) - Silinmedi, kullanıcı uyarıldı.",
                        AuditResult.Success,
                        cancellationToken: ct);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Failed to enforce warning for {Path}", evt.NormalizedPath);
            }
        }

        private async Task EnforceQuarantineAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct)
        {
            try
            {
                var fileInfo = new FileInfo(evt.NormalizedPath);
                var finding = new SecurityFinding
                {
                    ObjectPath = evt.NormalizedPath,
                    ObjectName = fileInfo.Name,
                    SHA256 = verdict.SHA256,
                    RiskLevel = verdict.RiskLevel,
                    RiskScore = verdict.RiskScore,
                    Category = FindingCategory.KnownMalwareHash,
                    Title = verdict.ThreatTitle,
                    Description = verdict.ThreatDescription,
                    RiskReasons = verdict.Evidences,
                    ConfidenceLevel = ConfidenceLevel.High,
                    FirstObserved = DateTime.UtcNow,
                    LastObserved = DateTime.UtcNow,
                    Status = FindingStatus.Active
                };

                // 1. ACTIVE PROCESS CONTAINMENT & TERMINATION
                int terminatedPid = 0;
                string terminatedProcName = string.Empty;
                try
                {
                    var runningProcesses = Process.GetProcesses();
                    foreach (var proc in runningProcesses)
                    {
                        try
                        {
                            if (proc.Id <= 4) continue;
                            if (CriticalProcesses.IsCriticalProcess(proc.ProcessName)) continue;

                            bool isTargetProcess = false;
                            try
                            {
                                if (string.Equals(proc.MainModule?.FileName, evt.NormalizedPath, StringComparison.OrdinalIgnoreCase))
                                {
                                    isTargetProcess = true;
                                }
                            }
                            catch { }

                            if (!isTargetProcess && evt.ProcessId > 0 && proc.Id == evt.ProcessId)
                            {
                                isTargetProcess = true;
                            }

                            if (isTargetProcess)
                            {
                                terminatedPid = proc.Id;
                                terminatedProcName = proc.ProcessName;
                                proc.Kill(entireProcessTree: true);
                                proc.WaitForExit(2000);
                                _logger?.LogWarning("Active malicious process terminated: {ProcName} (PID: {Pid})", terminatedProcName, terminatedPid);
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                // 2. Perform Secure AES-256 Quarantine
                bool quarantined = await _quarantineService.QuarantineFileAsync(evt.NormalizedPath, verdict.ThreatTitle, ct);
                if (quarantined)
                {
                    finding.Status = FindingStatus.Resolved;
                }

                // 3. Persist Finding to Database
                await _findingService.AddFindingAsync(finding, ct);

                // 4. Create Security Incident
                var incident = new SecurityIncident
                {
                    IncidentId = $"INC-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString("N")[..6].ToUpperInvariant()}",
                    Title = verdict.ThreatTitle,
                    ThreatName = verdict.ThreatTitle,
                    RootPid = terminatedPid,
                    RootProcessName = !string.IsNullOrEmpty(terminatedProcName) ? terminatedProcName : fileInfo.Name,
                    RootExecutablePath = evt.NormalizedPath,
                    RootHashSha256 = verdict.SHA256,
                    RiskScore = verdict.RiskScore,
                    RiskLevel = verdict.RiskLevel.ToString().ToUpperInvariant(),
                    CreatedAt = DateTime.UtcNow,
                    Status = quarantined ? "Quarantined" : "Active",
                    ActionTaken = terminatedPid > 0 
                        ? $"Aktif zararlı süreç (PID: {terminatedPid}) sonlandırıldı ve dosya AES-256 Karantina Kasasına kilitlendi."
                        : (quarantined ? "Dosya engellendi ve AES-256 Karantina Kasasına kilitlendi." : "Tespit Edildi"),
                    HumanExplanation = $"Gerçek zamanlı koruma kalkanı '{fileInfo.Name}' dosyasında kritik tehdit tespit etti." + 
                        (terminatedPid > 0 ? $" Çalışan zararlı süreç (PID: {terminatedPid}) derhal durduruldu." : "") + " Dosya güvenli şekilde karantinaya alındı.",
                    RecommendedUserAction = "Tehdit başarıyla etkisiz hale getirilmiştir. Gerekirse Karantina Kasası sayfasından inceleyebilirsiniz."
                };
                incident.Timeline.Add($"[{DateTime.UtcNow:HH:mm:ss}] Gerçek Zamanlı Koruma: '{fileInfo.Name}' tehdit deseni algılandı.");
                incident.Timeline.Add($"[{DateTime.UtcNow:HH:mm:ss}] Analiz Sonucu: Risk Skoru {verdict.RiskScore}/100 ({verdict.Verdict}).");
                if (terminatedPid > 0)
                {
                    incident.Timeline.Add($"[{DateTime.UtcNow:HH:mm:ss}] Müdahale: Aktif çalışan '{terminatedProcName}' (PID: {terminatedPid}) süreci zorla durduruldu.");
                }
                if (quarantined)
                {
                    incident.Timeline.Add($"[{DateTime.UtcNow:HH:mm:ss}] Karantina: Dosya diskten temizlendi ve AES-256 Kasaya kilitlendi.");
                }

                // 5. Raise UI Events & Windows Toast
                OnThreatDetected?.Invoke(finding);
                OnIncidentCreated?.Invoke(incident);

                string toastTitle = terminatedPid > 0 ? "🛑 Aktif Zararlı Süreç Durduruldu ve Kilitlendi!" : (quarantined ? "🛡️ Tehdit Engellendi ve Karantinaya Alındı!" : "🚨 Tehdit Tespit Edildi!");
                string toastMsg = terminatedPid > 0
                    ? $"'{terminatedProcName}' (PID: {terminatedPid}) süreci durduruldu ve '{fileInfo.Name}' dosyası karantinaya kilitlendi."
                    : $"'{fileInfo.Name}' dosyasında kritik tehdit tespit edildi ve anında engellendi.";

                OnNotificationRaised?.Invoke(toastTitle, toastMsg, "Danger");

                if (_auditLogService != null)
                {
                    await _auditLogService.LogActionAsync(
                        AuditAction.FileQuarantined,
                        "RealTimeShield",
                        fileInfo.Name,
                        evt.NormalizedPath,
                        $"{verdict.ThreatTitle} - Skor: {verdict.RiskScore}" + (terminatedPid > 0 ? $" - Süreç PID: {terminatedPid} sonlandırıldı." : ""),
                        AuditResult.Success,
                        cancellationToken: ct);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to enforce quarantine for {Path}", evt.NormalizedPath);
            }
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
