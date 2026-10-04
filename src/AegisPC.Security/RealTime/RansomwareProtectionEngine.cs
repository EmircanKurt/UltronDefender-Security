using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Core.Helpers;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    public class RansomwareAlertEventArgs : EventArgs
    {
        public string OffendingFilePath { get; set; } = string.Empty;
        public string OffendingProcessName { get; set; } = string.Empty;
        public int OffendingProcessId { get; set; }
        public string DetectionReason { get; set; } = string.Empty;
        public int RiskScore { get; set; }
        public bool ProcessTerminated { get; set; }
        public int FilesAffected { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public class RansomwareDamageAssessment
    {
        public int FilesTargeted { get; set; }
        public int FilesModified { get; set; }
        public int FilesRenamed { get; set; }
        public int FilesDeleted { get; set; }
        public int FilesBlocked { get; set; }
        public string OffendingProcess { get; set; } = string.Empty;
        public DateTime IncidentTime { get; set; } = DateTime.UtcNow;
    }

    public interface IRansomwareProtectionEngine
    {
        void StartShield();
        void StopShield();
        bool IsShieldActive { get; }
        IReadOnlyList<string> ProtectedDirectories { get; }
        IReadOnlyList<AllowedRansomwareApplication> AllowedApplications { get; }
        int CanaryFileCount { get; }
        int TotalBlockedAttempts { get; }
        void AddProtectedDirectory(string path);
        void RemoveProtectedDirectory(string path);
        void AddAllowedApplication(string executablePath, string? appName = null);
        void RemoveAllowedApplication(string executablePath);
        bool IsApplicationAllowed(string executablePath);
        void CleanupCanaryFiles();
        Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(string offendingPath, string reason, int riskScore, int pid = 0, DateTime? incidentTimestamp = null);
        event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected;
        event Action<string, string, string>? OnNotificationRaised;
    }

    /// <summary>
    /// Coordinates user-mode canary, entropy and file-change observations on explicit local roots.
    /// Heuristic observations are not confirmed malware, attributed attacker activity or kernel Controlled Folder Access.
    /// </summary>
    public class RansomwareProtectionEngine : IRansomwareProtectionEngine, IRansomwareCoverageProvider, IDisposable
    {
        private readonly ICanaryTrapManager _canaryManager;
        private readonly IEntropyBurstDetector _entropyBurstDetector;
        private readonly IProtectedFolderGate _folderGate;
        private readonly IRansomwareEnforcementHandler _enforcementHandler;
        private readonly ISignatureVerifier? _signatureVerifier;
        private readonly ILogger<RansomwareProtectionEngine>? _logger;

        private readonly List<FileSystemWatcher> _watchers = new();
        private bool _isActive;
        private bool _coverageGap;
        private bool _rootResolutionIncomplete;
        private readonly object _lock = new();

        public bool IsShieldActive { get { lock (_lock) return _isActive && _watchers.Count > 0; } }
        /// <summary>Samples active user-mode observers and historical unresolved loss, not pre-write blocking.</summary>
        public RansomwareCoverageSnapshot CaptureRansomwareCoverage()
        { lock (_lock) return new(_watchers.Count, _coverageGap || _rootResolutionIncomplete); }
        /// <summary>Retains profile resolution gaps separately from watcher failure or requested enabled state.</summary>
        public void SetRootResolutionIncomplete(bool incomplete) { lock (_lock) _rootResolutionIncomplete = incomplete; }
        public int CanaryFileCount => _canaryManager.CanaryFileCount;
        public int TotalBlockedAttempts => _enforcementHandler.TotalBlockedAttempts;
        public IReadOnlyList<string> ProtectedDirectories => _folderGate.ProtectedDirectories;
        public IReadOnlyList<AllowedRansomwareApplication> AllowedApplications => _folderGate.AllowedApplications;

        public event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected;
        public event Action<string, string, string>? OnNotificationRaised;

        public RansomwareProtectionEngine(
            ISignatureVerifier? signatureVerifier = null,
            IQuarantineService? quarantineService = null,
            ISecurityFindingService? findingService = null,
            IAuditLogService? auditLogService = null,
            ILogger<RansomwareProtectionEngine>? logger = null)
            : this(
                new CanaryTrapManager(),
                new EntropyBurstDetector(),
                new ProtectedFolderGate(logger),
                new RansomwareEnforcementHandler(quarantineService, findingService, auditLogService, logger),
                signatureVerifier,
                logger)
        {
        }

        public RansomwareProtectionEngine(
            ICanaryTrapManager canaryManager,
            IEntropyBurstDetector entropyBurstDetector,
            IProtectedFolderGate folderGate,
            IRansomwareEnforcementHandler enforcementHandler,
            ISignatureVerifier? signatureVerifier = null,
            ILogger<RansomwareProtectionEngine>? logger = null)
        {
            _canaryManager = canaryManager;
            _entropyBurstDetector = entropyBurstDetector;
            _folderGate = folderGate;
            _enforcementHandler = enforcementHandler;
            _signatureVerifier = signatureVerifier;
            _logger = logger;

            _enforcementHandler.OnRansomwareAttemptDetected += (s, e) => OnRansomwareAttemptDetected?.Invoke(this, e);
            _enforcementHandler.OnNotificationRaised += (title, msg, sev) => OnNotificationRaised?.Invoke(title, msg, sev);
        }

        public void StartShield()
        {
            lock (_lock)
            {
                if (_isActive) return;
                _isActive = true;
                _coverageGap = false;

                var localRoots = GetEligibleProtectionRoots();
                try { _canaryManager.DeployCanaries(localRoots); }
                catch (Exception exception)
                {
                    _isActive = false;
                    _coverageGap = true;
                    _logger?.LogWarning(exception, "Ransomware canary initialization failed; observation did not become active.");
                    throw;
                }

                foreach (var dir in localRoots)
                {
                    try
                    {
                        if (!Directory.Exists(dir)) { _coverageGap = true; continue; }

                        var watcher = new FileSystemWatcher(dir)
                        {
                            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                            IncludeSubdirectories = true,
                            InternalBufferSize = 32768
                        };

                        watcher.Renamed += OnFileRenamed;
                        watcher.Changed += OnFileModified;
                        watcher.Deleted += OnFileDeleted;
                        watcher.Created += OnFileCreated;
                        watcher.Error += (s, e) =>
                        {
                            lock (_lock)
                            {
                                if (!_isActive || !_watchers.Contains(watcher)) return;
                                _coverageGap = true;
                                _logger?.LogWarning(e.GetException(), "Ransomware file events were lost; continuity remains partial.");
                                try { watcher.EnableRaisingEvents = false; watcher.EnableRaisingEvents = true; }
                                catch (Exception exception) { _logger?.LogWarning(exception, "Ransomware observer could not restart."); }
                            }
                        };

                        _watchers.Add(watcher);
                        try { watcher.EnableRaisingEvents = true; }
                        catch { _watchers.Remove(watcher); watcher.Dispose(); throw; }
                    }
                    catch (Exception ex)
                    {
                        _coverageGap = true;
                        _logger?.LogTrace(ex, "Failed to start ransomware watcher for {Dir}", dir);
                    }
                }

                if (_watchers.Count == 0)
                {
                    _isActive = false; // A later explicit enable must be able to retry after the roots become available.
                    _coverageGap = true;
                    try { _canaryManager.CleanupCanaries(); }
                    catch (Exception exception) { _logger?.LogWarning(exception, "Inactive ransomware observer canaries could not be cleaned up."); }
                }
                _logger?.LogInformation("Ransomware observers registered across {Count} roots with {Canaries} canaries; coverage gap {Gap}. This is not kernel Controlled Folder Access.", _watchers.Count, _canaryManager.CanaryFileCount, _coverageGap);
            }
        }

        public void StopShield()
        {
            lock (_lock)
            {
                _isActive = false;
                foreach (var w in _watchers)
                {
                    try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
                }
                _watchers.Clear();

                _entropyBurstDetector.Clear();
                _canaryManager.CleanupCanaries();
            }
        }

        public void CleanupCanaryFiles()
        {
            _canaryManager.CleanupCanaries();
        }

        public void AddProtectedDirectory(string path)
        {
            lock (_lock)
            {
                _folderGate.AddProtectedDirectory(path);
                if (_isActive)
                {
                    StopShield();
                    StartShield();
                }
            }
        }

        public void RemoveProtectedDirectory(string path)
        {
            lock (_lock)
            {
                _folderGate.RemoveProtectedDirectory(path);
                if (_isActive)
                {
                    StopShield();
                    StartShield();
                }
            }
        }

        public void AddAllowedApplication(string executablePath, string? appName = null)
        {
            _folderGate.AddAllowedApplication(executablePath, appName);
        }

        public void RemoveAllowedApplication(string executablePath)
        {
            _folderGate.RemoveAllowedApplication(executablePath);
        }

        public bool IsApplicationAllowed(string executablePath)
        {
            return _folderGate.IsApplicationAllowed(executablePath);
        }

        public Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(string offendingPath, string reason, int riskScore, int pid = 0, DateTime? incidentTimestamp = null)
        {
            return _enforcementHandler.EvaluateAndContainThreatAsync(offendingPath, reason, riskScore, pid, IsApplicationAllowed, incidentTimestamp);
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (!AcceptImplicitFileEvent(e.FullPath)) return;
            CheckControlledFolderAccess(e.FullPath, "Yeni dosya oluşturuldu");
            _entropyBurstDetector.CheckRansomwareBurst(e.FullPath, "Yeni dosya oluşturuldu", (path, reason, score) =>
                EvaluateAndContainThreatAsync(path, reason, score));
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!AcceptImplicitFileEvent(e.FullPath) || !AcceptImplicitFileEvent(e.OldFullPath)) return;
            var newExt = Path.GetExtension(e.FullPath).ToLowerInvariant();

            if (_entropyBurstDetector.IsKnownRansomwareExtension(newExt))
            {
                _ = EvaluateAndContainThreatAsync(e.FullPath, $"🚨 Bilinen fidye şifreleme uzantısı tespit edildi: '{newExt}' (Eski: '{e.OldName}')", riskScore: 95);
                return;
            }

            if (_canaryManager.IsCanaryPath(e.OldFullPath) || _canaryManager.IsCanaryPath(e.FullPath))
            {
                _ = EvaluateAndContainThreatAsync(e.FullPath, "🚨 Kritik Tuzak İhlali: Kalkan Canary (yem) dosyası yeniden adlandırıldı veya şifreleniyor!", riskScore: 100);
                return;
            }

            CheckControlledFolderAccess(e.FullPath, "Dosya yeniden adlandırıldı");

            _entropyBurstDetector.CheckRansomwareBurst(e.FullPath, "Dosya yeniden adlandırıldı", (path, reason, score) =>
                EvaluateAndContainThreatAsync(path, reason, score));
        }

        private void OnFileModified(object sender, FileSystemEventArgs e)
        {
            if (!AcceptImplicitFileEvent(e.FullPath)) return;
            if (_canaryManager.IsCanaryPath(e.FullPath))
            {
                _ = EvaluateAndContainThreatAsync(e.FullPath, "🚨 Kritik Tuzak İhlali: Kalkan Canary dosyası izinsiz değiştirildi!", riskScore: 100);
                return;
            }

            CheckControlledFolderAccess(e.FullPath, "Dosya değiştirildi");

            _ = _entropyBurstDetector.CheckEntropyDeltaAsync(e.FullPath, (path, reason, score) =>
                EvaluateAndContainThreatAsync(path, reason, score));

            _entropyBurstDetector.CheckRansomwareBurst(e.FullPath, "Dosya değiştirildi", (path, reason, score) =>
                EvaluateAndContainThreatAsync(path, reason, score));
        }

        private void CheckControlledFolderAccess(string path, string action)
        {
            try
            {
                if (!_folderGate.IsPathInsideProtectedDirectory(path)) return;
                var pids = FileLockProcessResolver.FindLockingProcessIds(path);
                foreach (var pid in pids)
                {
                    if (pid <= 4 || pid == Environment.ProcessId) continue;
                    try
                    {
                        using var proc = System.Diagnostics.Process.GetProcessById(pid);
                        if (proc.HasExited) continue;
                        string procName = proc.ProcessName;
                        string procPath = string.Empty;
                        try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                        if (!_folderGate.IsApplicationAllowed(procName) && (string.IsNullOrEmpty(procPath) || !_folderGate.IsApplicationAllowed(procPath)))
                        {
                            _ = EvaluateAndContainThreatAsync(
                                path,
                                $"🚨 Korumalı Klasör İhlali: İzinli olmayan '{procName}' süreci ({action}) müdahalede bulundu!",
                                riskScore: 90,
                                pid: pid);
                            break;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (_canaryManager.IsCleaningUpCanaries) return;
            if (!AcceptImplicitFileEvent(e.FullPath)) return;

            if (_canaryManager.IsCanaryPath(e.FullPath))
            {
                _ = EvaluateAndContainThreatAsync(e.FullPath, "🚨 Kritik Tuzak İhlali: Kalkan Canary dosyası silindi! Fidye yazılımı izleri yok ediyor olabilir.", riskScore: 100);

                // Auto-recreate canary decoy after delay
                _ = Task.Run(async () =>
                {
                    await Task.Delay(3000);
                    lock (_lock)
                    {
                        if (_isActive)
                        {
                            _canaryManager.DeployCanaries(GetEligibleProtectionRoots());
                        }
                    }
                });
                return;
            }

            _entropyBurstDetector.CheckRansomwareBurst(e.FullPath, "Dosya silindi", (path, reason, score) =>
                EvaluateAndContainThreatAsync(path, reason, score));
        }

        public void Dispose()
        {
            StopShield();
            _entropyBurstDetector.Dispose();
        }

        private string[] GetEligibleProtectionRoots()
        {
            var declaredRoots = _folderGate.ProtectedDirectories;
            var localRoots = declaredRoots.Where(path => ImplicitLocalPathPolicy.IsEligible(path)).ToArray();
            if (localRoots.Length != declaredRoots.Count)
            {
                _coverageGap = true;
                _logger?.LogWarning("Non-local or reparse ransomware roots were not opened; coverage is partial.");
            }
            return localRoots;
        }

        private bool AcceptImplicitFileEvent(string path)
        {
            lock (_lock) if (!_isActive) return false;
            if (ImplicitLocalPathPolicy.IsEligible(path)) return true;
            lock (_lock) _coverageGap = true;
            _logger?.LogWarning("An implicit ransomware event path was not opened; observer coverage is partial.");
            return false;
        }
    }
}
