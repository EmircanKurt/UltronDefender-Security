using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    public class StartupSecuritySweepService : IStartupSecuritySweepService
    {
        private readonly IRealTimeProtectionEngine _realTimeEngine;
        private readonly IQuarantineService _quarantineService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ISettingsService? _settingsService;
        private readonly ILogger<StartupSecuritySweepService>? _logger;

        private StartupSweepStatus _status = StartupSweepStatus.NotStarted;
        private StartupSweepResult? _lastResult;
        private bool _isRunning;
        private readonly object _lock = new();
        private readonly SemaphoreSlim _sweepSemaphore = new(1, 1);

        // Cached file inspection metadata: Path -> (Size, LastWriteTimeUtc, SHA256, Verdict, RiskScore)
        private readonly ConcurrentDictionary<string, (long Size, DateTime LastWrite, string SHA256, string Verdict, int Score)> _fileCache = new(StringComparer.OrdinalIgnoreCase);
        private const int MaxFileCacheEntries = 100000;

        private static readonly HashSet<string> RiskyExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", 
            ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".sys"
        };

        private readonly ManualResetEventSlim _pauseEvent = new(true);
        private CancellationTokenSource? _activeSweepCts;

        public StartupSweepStatus Status
        {
            get { lock (_lock) return _status; }
            private set { lock (_lock) _status = value; }
        }

        public bool IsRunning
        {
            get { lock (_lock) return _isRunning; }
            private set { lock (_lock) _isRunning = value; }
        }

        public bool IsPaused => !_pauseEvent.IsSet;

        public void Pause()
        {
            _pauseEvent.Reset();
        }

        public void Resume()
        {
            _pauseEvent.Set();
        }

        public void Cancel()
        {
            try
            {
                _activeSweepCts?.Cancel();
            }
            catch { }
            _pauseEvent.Set();
        }

        public StartupSweepResult? LastResult
        {
            get { lock (_lock) return _lastResult; }
            private set { lock (_lock) _lastResult = value; }
        }

        public event Action<StartupSweepProgress>? OnProgressChanged;
        private readonly IScanCoordinatorService? _scanCoordinator;

        public event Action<StartupSweepFinding>? OnThreatDiscovered;
        public event Action<StartupSweepResult>? OnSweepCompleted;

        /// <summary>Creates a startup scanner; optional settings govern automatic hash-bound quarantine.</summary>
        public StartupSecuritySweepService(
            IRealTimeProtectionEngine realTimeEngine,
            IQuarantineService quarantineService,
            IAuditLogService? auditLogService = null,
            IScanCoordinatorService? scanCoordinator = null,
            ILogger<StartupSecuritySweepService>? logger = null,
            ISettingsService? settingsService = null)
        {
            _realTimeEngine = realTimeEngine;
            _quarantineService = quarantineService;
            _auditLogService = auditLogService;
            _settingsService = settingsService;
            _scanCoordinator = scanCoordinator;
            _logger = logger;
        }

        public void ClearCache()
        {
            _fileCache.Clear();
        }

        public async Task<StartupSweepResult> RunSweepAsync(
            IEnumerable<string>? customTargetDirs = null,
            CancellationToken cancellationToken = default)
        {
            await Task.Yield();

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _activeSweepCts = linkedCts;
            _pauseEvent.Set();

            using var coordSub = _scanCoordinator?.RegisterExternalScanner(
                pauseAction: () => Pause(),
                resumeAction: () => Resume(),
                cancelAction: () => Cancel());

            await _sweepSemaphore.WaitAsync(linkedCts.Token);
            try
            {
                lock (_lock)
                {
                    _isRunning = true;
                    _status = StartupSweepStatus.Preparing;
                }

                var stopwatch = Stopwatch.StartNew();
                var result = new StartupSweepResult();
                var progress = new StartupSweepProgress { Status = StartupSweepStatus.Preparing };
                NotifyProgress(progress);

            try
            {
                // 1. Gather attack surface directories
                var targetDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (customTargetDirs != null)
                {
                    foreach (var d in customTargetDirs)
                    {
                        if (Directory.Exists(d) || File.Exists(d))
                        {
                            targetDirs.Add(d);
                        }
                    }
                }
                else
                {
                    AddDefaultAttackSurfaceDirectories(targetDirs);
                }

                // 2. Discover Candidate Files
                var candidateFiles = new List<FileInfo>();
                foreach (var dir in targetDirs)
                {
                    if (linkedCts.Token.IsCancellationRequested) break;
                    _pauseEvent.Wait(linkedCts.Token);
                    DiscoverCandidateFiles(dir, candidateFiles, linkedCts.Token);
                }

                if (linkedCts.Token.IsCancellationRequested)
                {
                    return HandleCancelledSweep(result, progress, stopwatch);
                }

                // Sort: Prioritize by Risk Location (Startup -> Downloads -> Desktop -> Temp -> AppData -> Documents)
                // NEVER sort by file size!
                candidateFiles = candidateFiles
                    .OrderBy(f => GetLocationRiskPriority(f.FullName))
                    .ThenByDescending(f => f.LastWriteTimeUtc)
                    .ToList();

                progress.TotalFiles = candidateFiles.Count;
                progress.Status = StartupSweepStatus.Scanning;
                Status = StartupSweepStatus.Scanning;
                NotifyProgress(progress);

                // 3. Snapshot Running Processes for Correlation
                var processMap = BuildRunningProcessMap();

                // 4. Perform Progressive Scan on Candidates
                foreach (var file in candidateFiles)
                {
                    if (linkedCts.Token.IsCancellationRequested) break;
                    _pauseEvent.Wait(linkedCts.Token);

                    if (!File.Exists(file.FullName))
                    {
                        continue;
                    }

                    progress.CurrentFile = file.Name;
                    progress.ScannedFiles++;

                    // Check Cache for unchanged clean files
                    if (_fileCache.TryGetValue(file.FullName, out var cached) &&
                        cached.Size == file.Length &&
                        cached.LastWrite == file.LastWriteTimeUtc &&
                        cached.Verdict == "Clean" &&
                        await HasExpectedContentAsync(file.FullName, cached.SHA256, linkedCts.Token))
                    {
                        progress.CleanFiles++;
                        progress.SkippedUnchanged++;
                        result.CleanCount++;
                        result.SkippedCount++;
                        NotifyProgress(progress);
                        continue;
                    }

                    // Inspect file with RealTime engine pipeline
                    var verdictResult = await _realTimeEngine.InspectFileAsync(file.FullName, linkedCts.Token);
                    var correlationId = Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();

                    // Check if file matches any running process
                    bool hasProc = processMap.TryGetValue(file.FullName.ToLowerInvariant(), out var procInfo);

                    bool exactThreat = verdictResult.Verdict == RealTimeVerdict.ConfirmedMalicious &&
                        verdictResult.RecommendedPolicy == RealTimePolicyAction.BlockAndQuarantine &&
                        IsSha256(verdictResult.SHA256) &&
                        await HasExpectedContentAsync(file.FullName, verdictResult.SHA256, linkedCts.Token);
                    if (exactThreat)
                    {
                        // THREAT FOUND!
                        progress.ThreatsFound++;
                        result.ThreatsCount++;

                        var finding = new StartupSweepFinding
                        {
                            FilePath = file.FullName,
                            FileName = file.Name,
                            SHA256 = verdictResult.SHA256,
                            FileSize = file.Length,
                            CreatedAt = file.CreationTimeUtc,
                            ModifiedAt = file.LastWriteTimeUtc,
                            RiskScore = verdictResult.RiskScore,
                            Verdict = verdictResult.Verdict.ToString(),
                            Action = "DETECTED",
                            Evidences = new List<string>(verdictResult.Evidences),
                            CorrelationId = correlationId,
                            DetectionTime = DateTime.UtcNow,
                            IsRunningProcess = hasProc,
                            ProcessId = hasProc ? procInfo.ProcessId : 0,
                            ParentProcessId = hasProc ? procInfo.ParentProcessId : 0,
                            ProcessName = hasProc ? procInfo.ProcessName : string.Empty,
                            ProcessStartTime = hasProc ? procInfo.StartTime : null
                        };

                        // A path/process snapshot does not prove live process identity. Do not terminate a PID here.
                        bool autoQuarantineEnabled = _settingsService?.GetSetting("EnableAutoQuarantine", true) ?? true;
                        int threshold = Math.Clamp(_settingsService?.GetSetting("AutoQuarantineThreshold", 85) ?? 85, 1, 100);
                        bool canQuarantine = autoQuarantineEnabled && verdictResult.RiskScore >= threshold &&
                            _quarantineService is IContentBoundQuarantineService;
                        bool quarantined = false;
                        if (canQuarantine)
                        {
                            var contentBound = (IContentBoundQuarantineService)_quarantineService;
                            quarantined = await contentBound.TryQuarantineFileAsync(
                                file.FullName,
                                $"Startup Security Sweep: {verdictResult.ThreatTitle}",
                                verdictResult.SHA256,
                                linkedCts.Token);
                        }

                        finding.IsQuarantined = quarantined;
                        if (canQuarantine)
                            finding.Action = quarantined ? "QUARANTINED" : "QUARANTINE_FAILED";
                        else
                            finding.Action = "REVIEW_REQUIRED";
                        finding.ActionTime = DateTime.UtcNow;

                        result.Findings.Add(finding);
                        OnThreatDiscovered?.Invoke(finding);

                        if (_auditLogService != null && canQuarantine)
                        {
                            await _auditLogService.LogActionAsync(
                                AuditAction.FileQuarantined,
                                "StartupSweep",
                                file.Name,
                                file.FullName,
                                $"Startup Security Sweep tehdit tespit etti: {verdictResult.ThreatTitle} (Skor: {verdictResult.RiskScore})",
                                quarantined ? AuditResult.Success : AuditResult.Failed,
                                cancellationToken: linkedCts.Token);
                        }
                    }
                    else if (verdictResult.Verdict == RealTimeVerdict.Unknown)
                    {
                        progress.IncompleteCount++;
                        result.IncompleteCount++;
                        result.Findings.Add(new StartupSweepFinding
                        {
                            FilePath = file.FullName,
                            FileName = file.Name,
                            SHA256 = verdictResult.SHA256,
                            FileSize = file.Length,
                            RiskScore = verdictResult.RiskScore,
                            Verdict = nameof(RealTimeVerdict.Unknown),
                            Action = "INCOMPLETE",
                            Evidences = new List<string>(verdictResult.Evidences),
                            CorrelationId = correlationId,
                            DetectionTime = DateTime.UtcNow,
                            ActionTime = DateTime.UtcNow
                        });
                    }
                    else if (verdictResult.Verdict != RealTimeVerdict.Clean ||
                             verdictResult.RecommendedPolicy == RealTimePolicyAction.Warn ||
                             verdictResult.RecommendedPolicy == RealTimePolicyAction.BlockAndQuarantine ||
                             verdictResult.RiskScore >= 50)
                    {
                        // SUSPICIOUS FILE
                        progress.SuspiciousFound++;
                        result.SuspiciousCount++;

                        var finding = new StartupSweepFinding
                        {
                            FilePath = file.FullName,
                            FileName = file.Name,
                            SHA256 = verdictResult.SHA256,
                            FileSize = file.Length,
                            CreatedAt = file.CreationTimeUtc,
                            ModifiedAt = file.LastWriteTimeUtc,
                            RiskScore = verdictResult.RiskScore,
                            Verdict = nameof(RealTimeVerdict.Suspicious),
                            Action = "WARN",
                            Evidences = new List<string>(verdictResult.Evidences),
                            CorrelationId = correlationId,
                            DetectionTime = DateTime.UtcNow,
                            ActionTime = DateTime.UtcNow,
                            IsQuarantined = false,
                            IsRunningProcess = hasProc,
                            ProcessId = hasProc ? procInfo.ProcessId : 0,
                            ParentProcessId = hasProc ? procInfo.ParentProcessId : 0,
                            ProcessName = hasProc ? procInfo.ProcessName : string.Empty,
                            ProcessStartTime = hasProc ? procInfo.StartTime : null
                        };

                        result.Findings.Add(finding);
                        OnThreatDiscovered?.Invoke(finding);

                        CacheFileVerdict(file, verdictResult.SHA256, "Suspicious", verdictResult.RiskScore);
                    }
                    else
                    {
                        // CLEAN
                        progress.CleanFiles++;
                        result.CleanCount++;

                        var finding = new StartupSweepFinding
                        {
                            FilePath = file.FullName,
                            FileName = file.Name,
                            SHA256 = verdictResult.SHA256,
                            FileSize = file.Length,
                            CreatedAt = file.CreationTimeUtc,
                            ModifiedAt = file.LastWriteTimeUtc,
                            RiskScore = verdictResult.RiskScore,
                            Verdict = verdictResult.Verdict.ToString(),
                            Action = "ALLOW",
                            Evidences = new List<string>(verdictResult.Evidences)
                        };
                        result.Findings.Add(finding);

                        if (IsSha256(verdictResult.SHA256))
                            CacheFileVerdict(file, verdictResult.SHA256, "Clean", verdictResult.RiskScore);
                    }

                    NotifyProgress(progress);
                }

                if (linkedCts.Token.IsCancellationRequested)
                {
                    return HandleCancelledSweep(result, progress, stopwatch);
                }

                stopwatch.Stop();
                result.Duration = stopwatch.Elapsed;
                result.TotalScanned = progress.ScannedFiles;
                result.FinalStatus = result.IncompleteCount > 0
                    ? StartupSweepStatus.Failed
                    : result.ThreatsCount > 0
                    ? StartupSweepStatus.ThreatsFound 
                    : (result.SuspiciousCount > 0 ? StartupSweepStatus.Completed : StartupSweepStatus.Clean);

                progress.Status = result.FinalStatus;
                Status = result.FinalStatus;
                LastResult = result;

                NotifyProgress(progress);
                NotifyCompleted(result, stopwatch.Elapsed);

                return result;
            }
            catch (OperationCanceledException)
            {
                _logger?.LogInformation("Startup Security Sweep was cancelled.");
                return HandleCancelledSweep(result, progress, stopwatch);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SWEEP EXCEPTION] {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
                _logger?.LogError(ex, "Startup Security Sweep failed unexpectedly.");
                Status = StartupSweepStatus.Failed;
                result.FinalStatus = StartupSweepStatus.Failed;
                return result;
            }
            finally
            {
                lock (_lock)
                {
                    _isRunning = false;
                }
            }
        }
        finally
        {
            _sweepSemaphore.Release();
        }
    }

        private StartupSweepResult HandleCancelledSweep(
            StartupSweepResult result,
            StartupSweepProgress progress,
            Stopwatch stopwatch)
        {
            stopwatch.Stop();
            result.Duration = stopwatch.Elapsed;
            result.TotalScanned = progress.ScannedFiles;
            result.FinalStatus = StartupSweepStatus.Cancelled;

            progress.Status = StartupSweepStatus.Cancelled;
            Status = StartupSweepStatus.Cancelled;
            LastResult = result;

            NotifyProgress(progress);
            NotifyCompleted(result, stopwatch.Elapsed);

            return result;
        }

        private void CacheFileVerdict(FileInfo file, string sha256, string verdict, int score)
        {
            if (_fileCache.Count >= MaxFileCacheEntries)
            {
                _fileCache.Clear();
                _logger?.LogWarning("Startup scan cache reached its {Limit} entry limit and was cleared.", MaxFileCacheEntries);
            }
            _fileCache[file.FullName] = (file.Length, file.LastWriteTimeUtc, sha256, verdict, score);
        }

        private static bool IsSha256(string? value) =>
            value is { Length: 64 } && value.All(Uri.IsHexDigit);

        private static async Task<bool> HasExpectedContentAsync(string path, string expectedSha256, CancellationToken ct)
        {
            if (!IsSha256(expectedSha256)) return false;
            try
            {
                await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, 65536,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                var actual = await SHA256.HashDataAsync(stream, ct);
                return Convert.ToHexString(actual).Equals(expectedSha256, StringComparison.OrdinalIgnoreCase);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        private void NotifyProgress(StartupSweepProgress progress)
        {
            OnProgressChanged?.Invoke(progress);
            if (_scanCoordinator != null)
            {
                _scanCoordinator.RegisterExternalScanProgress(new ScanProgress
                {
                    ScanType = ScanType.Quick,
                    CurrentFile = progress.CurrentFile,
                    ScannedFiles = progress.ScannedFiles,
                    TotalFiles = progress.TotalFiles,
                    FindingsCount = progress.ThreatsFound + progress.SuspiciousFound,
                    ProgressPercent = progress.ProgressPercent
                });
            }
        }

        private void NotifyCompleted(StartupSweepResult result, TimeSpan duration)
        {
            OnSweepCompleted?.Invoke(result);
            if (_scanCoordinator != null)
            {
                _scanCoordinator.CompleteExternalScan(new ScanResult
                {
                    ScanType = ScanType.Quick,
                    ScannedFiles = result.TotalScanned,
                    TotalFiles = result.TotalScanned,
                    ElapsedMs = (long)duration.TotalMilliseconds,
                    Status = result.FinalStatus switch
                    {
                        StartupSweepStatus.Cancelled => ScanStatus.Cancelled,
                        StartupSweepStatus.Failed => ScanStatus.Failed,
                        _ => ScanStatus.Completed
                    },
                    CompletedAt = DateTime.UtcNow,
                    Findings = result.Findings
                        .Where(f => f.IsQuarantined || f.Action == "QUARANTINED" || f.RiskScore >= 50)
                        .Select(f => new SecurityFinding
                        {
                            ObjectName = f.FileName,
                            ObjectPath = f.FilePath,
                            RiskScore = f.RiskScore,
                            RiskLevel = f.Verdict == nameof(RealTimeVerdict.ConfirmedMalicious)
                                ? RiskLevel.ConfirmedMalicious
                                : f.RiskScore switch
                            {
                                >= 70 => RiskLevel.HighRisk,
                                >= 50 => RiskLevel.Suspicious,
                                _ => RiskLevel.LowRisk
                            },
                            Title = f.Verdict == nameof(RealTimeVerdict.ConfirmedMalicious)
                                ? $"Başlangıç Tehdidi: {f.FileName}"
                                : $"Başlangıç Uyarısı: {f.FileName}",
                            Description = string.Join("; ", f.Evidences),
                            Status = f.IsQuarantined ? FindingStatus.Resolved : FindingStatus.Active
                        }).ToList()
                });
            }
        }

        private void AddDefaultAttackSurfaceDirectories(HashSet<string> targetDirs)
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            // 1. Startup Folders (Highest Priority)
            var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (Directory.Exists(userStartup)) targetDirs.Add(userStartup);

            var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            if (Directory.Exists(commonStartup)) targetDirs.Add(commonStartup);

            // 2. Downloads
            var downloads = Path.Combine(userProfile, "Downloads");
            if (Directory.Exists(downloads)) targetDirs.Add(downloads);

            // 3. Desktop
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (Directory.Exists(desktop)) targetDirs.Add(desktop);

            // 4. Temp folders
            var temp = Path.GetTempPath();
            if (Directory.Exists(temp)) targetDirs.Add(temp);

            var localTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");
            if (Directory.Exists(localTemp)) targetDirs.Add(localTemp);

            // 5. AppData Roaming
            var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (Directory.Exists(appDataRoaming)) targetDirs.Add(appDataRoaming);

            // 6. Documents
            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (Directory.Exists(documents)) targetDirs.Add(documents);
        }

        private void DiscoverCandidateFiles(string dirPath, List<FileInfo> candidates, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(dirPath) || cancellationToken.IsCancellationRequested) return;
            string fullPath = Path.GetFullPath(dirPath);

            if (File.Exists(fullPath))
            {
                try
                {
                    candidates.Add(new FileInfo(fullPath));
                }
                catch { }
                return;
            }

            if (!Directory.Exists(fullPath)) return;

            var stack = new Stack<string>();
            stack.Push(fullPath);

            while (stack.Count > 0)
            {
                if (cancellationToken.IsCancellationRequested) break;
                var currentDir = stack.Pop();
                if (!Directory.Exists(currentDir)) continue;

                var dirName = Path.GetFileName(currentDir);
                if (FileScannerService.ExcludedDirectoryNames.Contains(dirName))
                    continue;

                try
                {
                    var files = Directory.GetFiles(currentDir, "*");
                    foreach (var filePath in files)
                    {
                        if (cancellationToken.IsCancellationRequested) break;
                        try
                        {
                            var ext = Path.GetExtension(filePath);
                            if (!string.IsNullOrEmpty(ext) && FileScannerService.SafeMediaExtensions.Contains(ext))
                                continue;

                            var fileName = Path.GetFileName(filePath);
                            bool isDoubleExtensionThreat = fileName.Count(c => c == '.') > 1 && RiskyExtensions.Contains(ext);
                            if (RiskyExtensions.Contains(ext) || isDoubleExtensionThreat)
                            {
                                candidates.Add(new FileInfo(filePath));
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                try
                {
                    var subDirs = Directory.GetDirectories(currentDir);
                    foreach (var sub in subDirs)
                    {
                        if (cancellationToken.IsCancellationRequested) break;
                        stack.Push(sub);
                    }
                }
                catch { }
            }
        }

        private static int GetLocationRiskPriority(string fullPath)
        {
            if (fullPath.Contains(@"\Startup", StringComparison.OrdinalIgnoreCase) ||
                fullPath.Contains(@"\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase))
                return 1;

            if (fullPath.Contains(@"\Downloads", StringComparison.OrdinalIgnoreCase))
                return 2;

            if (fullPath.Contains(@"\Desktop", StringComparison.OrdinalIgnoreCase))
                return 3;

            if (fullPath.Contains(@"\Temp", StringComparison.OrdinalIgnoreCase))
                return 4;

            if (fullPath.Contains(@"\AppData\Roaming", StringComparison.OrdinalIgnoreCase))
                return 5;

            if (fullPath.Contains(@"\Documents", StringComparison.OrdinalIgnoreCase))
                return 6;

            return 7;
        }

        private Dictionary<string, (int ProcessId, int ParentProcessId, string ProcessName, DateTime? StartTime)> BuildRunningProcessMap()
        {
            var map = new Dictionary<string, (int, int, string, DateTime?)>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var parentMap = new Dictionary<int, int>();
                var handle = CreateToolhelp32Snapshot(2, 0);
                if (handle != IntPtr.Zero && handle != (IntPtr)(-1))
                {
                    try
                    {
                        var pe = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32)) };
                        if (Process32First(handle, ref pe))
                        {
                            do
                            {
                                parentMap[(int)pe.th32ProcessID] = (int)pe.th32ParentProcessID;
                            } while (Process32Next(handle, ref pe));
                        }
                    }
                    finally
                    {
                        CloseHandle(handle);
                    }
                }

                var processes = Process.GetProcesses();
                foreach (var proc in processes)
                {
                    try
                    {
                        if (proc.Id <= 4) continue;
                        var path = proc.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(path))
                        {
                            DateTime? startTime = null;
                            try { startTime = proc.StartTime; } catch { }

                            parentMap.TryGetValue(proc.Id, out int parentId);
                            map[path.ToLowerInvariant()] = (proc.Id, parentId, proc.ProcessName, startTime);
                        }
                    }
                    catch { }
                    finally
                    {
                        proc.Dispose();
                    }
                }
            }
            catch { }
            return map;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }
    }
}
