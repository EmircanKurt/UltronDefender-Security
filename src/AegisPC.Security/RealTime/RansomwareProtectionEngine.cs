using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
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
        Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(string offendingPath, string reason, int riskScore, int pid = 0);
        event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected;
        event Action<string, string, string>? OnNotificationRaised;
    }

    /// <summary>
    /// Windows Controlled Folder Access modeli, Canary tuzakları, kitle modifikasyon anomalisi ve
    /// entropi delta analizine sahip tam teşekküllü Fidye Yazılımı Savunma Orkestratörü.
    /// Modüler mimaride CanaryTrapManager, EntropyBurstDetector, ProtectedFolderGate ve RansomwareEnforcementHandler bileşenlerini koordine eder.
    /// </summary>
    public class RansomwareProtectionEngine : IRansomwareProtectionEngine, IDisposable
    {
        private readonly ICanaryTrapManager _canaryManager;
        private readonly IEntropyBurstDetector _entropyBurstDetector;
        private readonly IProtectedFolderGate _folderGate;
        private readonly IRansomwareEnforcementHandler _enforcementHandler;
        private readonly ISignatureVerifier? _signatureVerifier;
        private readonly ILogger<RansomwareProtectionEngine>? _logger;

        private readonly List<FileSystemWatcher> _watchers = new();
        private bool _isActive;
        private readonly object _lock = new();

        public bool IsShieldActive => _isActive;
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

                _canaryManager.DeployCanaries(_folderGate.ProtectedDirectories);

                foreach (var dir in _folderGate.ProtectedDirectories)
                {
                    try
                    {
                        if (!Directory.Exists(dir)) continue;

                        var watcher = new FileSystemWatcher(dir)
                        {
                            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                            IncludeSubdirectories = true,
                            InternalBufferSize = 32768,
                            EnableRaisingEvents = true
                        };

                        watcher.Renamed += OnFileRenamed;
                        watcher.Changed += OnFileModified;
                        watcher.Deleted += OnFileDeleted;
                        watcher.Created += OnFileCreated;
                        watcher.Error += (s, e) =>
                        {
                            try
                            {
                                watcher.EnableRaisingEvents = false;
                                watcher.EnableRaisingEvents = true;
                            }
                            catch { }
                        };

                        _watchers.Add(watcher);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "Failed to start ransomware watcher for {Dir}", dir);
                    }
                }

                _logger?.LogInformation("Ransomware Defense Engine activated across {Count} directories with {Canaries} canary decoys.", _folderGate.ProtectedDirectories.Count, _canaryManager.CanaryFileCount);
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

        public Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(string offendingPath, string reason, int riskScore, int pid = 0)
        {
            return _enforcementHandler.EvaluateAndContainThreatAsync(offendingPath, reason, riskScore, pid, IsApplicationAllowed);
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            _entropyBurstDetector.CheckRansomwareBurst(e.FullPath, "Yeni dosya oluşturuldu", (path, reason, score) =>
                EvaluateAndContainThreatAsync(path, reason, score));
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            var newExt = Path.GetExtension(e.FullPath).ToLowerInvariant();

            if (_entropyBurstDetector.IsKnownRansomwareExtension(newExt))
            {
                _ = EvaluateAndContainThreatAsync(e.FullPath, $"🚨 Bilinen fidye şifreleme uzantısı tespit edildi: '{newExt}' (Eski: '{e.OldName}')", riskScore: 95);
                return;
            }

            if (_canaryManager.IsCanaryPath(e.OldFullPath))
            {
                _ = EvaluateAndContainThreatAsync(e.FullPath, "🚨 Kritik Tuzak İhlali: Kalkan Canary (yem) dosyası yeniden adlandırıldı veya şifreleniyor!", riskScore: 100);
                return;
            }

            _entropyBurstDetector.CheckRansomwareBurst(e.FullPath, "Dosya yeniden adlandırıldı", (path, reason, score) =>
                EvaluateAndContainThreatAsync(path, reason, score));
        }

        private void OnFileModified(object sender, FileSystemEventArgs e)
        {
            if (_canaryManager.IsCanaryPath(e.FullPath))
            {
                _ = EvaluateAndContainThreatAsync(e.FullPath, "🚨 Kritik Tuzak İhlali: Kalkan Canary dosyası izinsiz değiştirildi!", riskScore: 100);
                return;
            }

            _ = _entropyBurstDetector.CheckEntropyDeltaAsync(e.FullPath, (path, reason, score) =>
                EvaluateAndContainThreatAsync(path, reason, score));

            _entropyBurstDetector.CheckRansomwareBurst(e.FullPath, "Dosya değiştirildi", (path, reason, score) =>
                EvaluateAndContainThreatAsync(path, reason, score));
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (_canaryManager.IsCleaningUpCanaries) return;

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
                            _canaryManager.DeployCanaries(_folderGate.ProtectedDirectories);
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
    }
}
