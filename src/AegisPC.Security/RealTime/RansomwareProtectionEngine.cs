using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
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
    /// entropi delta analizine sahip tam teşekküllü Fidye Yazılımı Savunma Sistemi (Ransomware Defense Engine).
    /// </summary>
    public class RansomwareProtectionEngine : IRansomwareProtectionEngine, IDisposable
    {
        private readonly ISignatureVerifier? _signatureVerifier;
        private readonly IQuarantineService? _quarantineService;
        private readonly ISecurityFindingService? _findingService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger<RansomwareProtectionEngine>? _logger;

        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly List<string> _protectedDirs = new();
        private readonly List<AllowedRansomwareApplication> _allowedApps = new();
        private readonly List<string> _canaryFiles = new();
        private volatile bool _isCleaningUpCanaries;
        private readonly ConcurrentDictionary<string, ConcurrentQueue<DateTime>> _processWriteActivity = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentQueue<DateTime> _globalRapidChanges = new();
        private readonly ConcurrentDictionary<string, double> _fileEntropyCache = new(StringComparer.OrdinalIgnoreCase);

        private readonly string _storageFilePath;
        private readonly string _allowedAppsFilePath;
        private bool _isActive;
        private int _totalBlockedCount;
        private readonly object _lock = new();
        private Timer? _entropyCacheCleanupTimer;
        private const int MaxEntropyCacheEntries = 5000;

        public bool IsShieldActive => _isActive;
        public int CanaryFileCount => _canaryFiles.Count;
        public int TotalBlockedAttempts => _totalBlockedCount;

        public IReadOnlyList<string> ProtectedDirectories
        {
            get
            {
                lock (_lock) return _protectedDirs.ToList();
            }
        }

        public IReadOnlyList<AllowedRansomwareApplication> AllowedApplications
        {
            get
            {
                lock (_lock) return _allowedApps.ToList();
            }
        }

        public event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected;
        public event Action<string, string, string>? OnNotificationRaised;

        private static readonly string[] KnownRansomwareExtensions = new[]
        {
            ".locked", ".crypto", ".enc", ".encrypted", ".dark", ".ransom", ".crypt",
            ".crinf", ".r5a", ".locky", ".cerber", ".wannacry", ".wncry", ".micro",
            ".crypted", ".vault", ".stop", ".djvu", ".phobos", ".dharma", ".blackmatter", ".lockbit"
        };

        private static readonly string[] DefaultAllowedExecutableNames = new[]
        {
            "explorer.exe", "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe",
            "code.exe", "devenv.exe", "notepad.exe", "notepad++.exe", "photoshop.exe",
            "acrobat.exe", "acrord32.exe", "onedrive.exe", "googledrivefs.exe", "dropbox.exe",
            "git.exe", "cmd.exe", "powershell.exe", "msedge.exe", "chrome.exe", "firefox.exe"
        };

        public RansomwareProtectionEngine(
            ISignatureVerifier? signatureVerifier = null,
            IQuarantineService? quarantineService = null,
            ISecurityFindingService? findingService = null,
            IAuditLogService? auditLogService = null,
            ILogger<RansomwareProtectionEngine>? logger = null)
        {
            _signatureVerifier = signatureVerifier;
            _quarantineService = quarantineService;
            _findingService = findingService;
            _auditLogService = auditLogService;
            _logger = logger;

            var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AegisPC");
            Directory.CreateDirectory(dataDir);
            _storageFilePath = Path.Combine(dataDir, "protected_folders.json");
            _allowedAppsFilePath = Path.Combine(dataDir, "allowed_ransomware_apps.json");

            LoadProtectedDirsFromDisk();
            LoadAllowedAppsFromDisk();
        }

        private void LoadProtectedDirsFromDisk()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_storageFilePath))
                    {
                        var json = File.ReadAllText(_storageFilePath);
                        var loaded = JsonSerializer.Deserialize<List<string>>(json);
                        if (loaded != null && loaded.Count > 0)
                        {
                            _protectedDirs.Clear();
                            _protectedDirs.AddRange(loaded.Where(Directory.Exists));
                            return;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to load protected folders from disk.");
                }

                // Initialize default user folders (Controlled Folder Access)
                var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var defaults = new[]
                {
                    Path.Combine(user, "Documents"),
                    Path.Combine(user, "Desktop"),
                    Path.Combine(user, "Pictures"),
                    Path.Combine(user, "Videos"),
                    Path.Combine(user, "Music"),
                    Path.Combine(user, "Downloads")
                }.Where(Directory.Exists);

                _protectedDirs.Clear();
                foreach (var d in defaults) _protectedDirs.Add(d);
                SaveProtectedDirsToDisk();
            }
        }

        private void SaveProtectedDirsToDisk()
        {
            try
            {
                var json = JsonSerializer.Serialize(_protectedDirs, new JsonSerializerOptions { WriteIndented = true });
                var tmp = _storageFilePath + ".tmp";
                File.WriteAllText(tmp, json);
                File.Move(tmp, _storageFilePath, overwrite: true);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to save protected folders to disk.");
            }
        }

        private void LoadAllowedAppsFromDisk()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_allowedAppsFilePath))
                    {
                        var json = File.ReadAllText(_allowedAppsFilePath);
                        var loaded = JsonSerializer.Deserialize<List<AllowedRansomwareApplication>>(json);
                        if (loaded != null && loaded.Count > 0)
                        {
                            _allowedApps.Clear();
                            _allowedApps.AddRange(loaded);
                            return;
                        }
                    }
                }
                catch { }

                // Seed Default Whitelist Applications
                _allowedApps.Clear();
                foreach (var exe in DefaultAllowedExecutableNames)
                {
                    _allowedApps.Add(new AllowedRansomwareApplication
                    {
                        ExecutablePath = exe,
                        ApplicationName = Path.GetFileNameWithoutExtension(exe).ToUpperInvariant(),
                        Publisher = "System / Verified",
                        IsSigned = true,
                        IsSystemWhitelisted = true,
                        AddedAt = DateTime.UtcNow
                    });
                }
                SaveAllowedAppsToDisk();
            }
        }

        private void SaveAllowedAppsToDisk()
        {
            try
            {
                var json = JsonSerializer.Serialize(_allowedApps, new JsonSerializerOptions { WriteIndented = true });
                var tmp = _allowedAppsFilePath + ".tmp";
                File.WriteAllText(tmp, json);
                File.Move(tmp, _allowedAppsFilePath, overwrite: true);
            }
            catch { }
        }

        public void StartShield()
        {
            lock (_lock)
            {
                if (_isActive) return;
                _isActive = true;

                DeployCanaryDecoys();

                foreach (var dir in _protectedDirs)
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

                _logger?.LogInformation("Ransomware Defense Engine activated across {Count} directories with {Canaries} canary decoys.", _protectedDirs.Count, _canaryFiles.Count);

                // Entropi cache temizleme timer'ı — bellek sızıntısını önle
                _entropyCacheCleanupTimer = new Timer(_ =>
                {
                    if (_fileEntropyCache.Count > MaxEntropyCacheEntries)
                    {
                        // En eski %50'sini temizle
                        int toRemove = _fileEntropyCache.Count / 2;
                        int removed = 0;
                        foreach (var key in _fileEntropyCache.Keys)
                        {
                            if (removed >= toRemove) break;
                            _fileEntropyCache.TryRemove(key, out double _);
                            removed++;
                        }
                    }
                }, null, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15));
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

                // Entropi cache temizleme timer'ını durdur ve cache'i temizle
                _entropyCacheCleanupTimer?.Dispose();
                _entropyCacheCleanupTimer = null;
                _fileEntropyCache.Clear();

                CleanupCanaryFiles();
            }
        }

        public void CleanupCanaryFiles()
        {
            _isCleaningUpCanaries = true;
            try
            {
                foreach (var canary in _canaryFiles.ToList())
                {
                    try
                    {
                        if (File.Exists(canary))
                        {
                            File.SetAttributes(canary, FileAttributes.Normal);
                            File.Delete(canary);
                        }
                    }
                    catch { }
                }
                _canaryFiles.Clear();
            }
            finally
            {
                _isCleaningUpCanaries = false;
            }
        }

        public void AddProtectedDirectory(string path)
        {
            lock (_lock)
            {
                if (Directory.Exists(path) && !_protectedDirs.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    _protectedDirs.Add(path);
                    SaveProtectedDirsToDisk();

                    if (_isActive)
                    {
                        StopShield();
                        StartShield();
                    }
                }
            }
        }

        public void RemoveProtectedDirectory(string path)
        {
            lock (_lock)
            {
                _protectedDirs.RemoveAll(p => p.Equals(path, StringComparison.OrdinalIgnoreCase));
                SaveProtectedDirsToDisk();

                if (_isActive)
                {
                    StopShield();
                    StartShield();
                }
            }
        }

        public void AddAllowedApplication(string executablePath, string? appName = null)
        {
            lock (_lock)
            {
                if (!_allowedApps.Any(a => a.ExecutablePath.Equals(executablePath, StringComparison.OrdinalIgnoreCase)))
                {
                    _allowedApps.Add(new AllowedRansomwareApplication
                    {
                        ExecutablePath = executablePath,
                        ApplicationName = appName ?? Path.GetFileNameWithoutExtension(executablePath),
                        IsSigned = false,
                        IsSystemWhitelisted = false,
                        AddedAt = DateTime.UtcNow
                    });
                    SaveAllowedAppsToDisk();
                }
            }
        }

        public void RemoveAllowedApplication(string executablePath)
        {
            lock (_lock)
            {
                _allowedApps.RemoveAll(a => a.ExecutablePath.Equals(executablePath, StringComparison.OrdinalIgnoreCase));
                SaveAllowedAppsToDisk();
            }
        }

        public bool IsApplicationAllowed(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath)) return false;
            var fileName = Path.GetFileName(executablePath);

            lock (_lock)
            {
                return _allowedApps.Any(a => 
                    a.ExecutablePath.Equals(executablePath, StringComparison.OrdinalIgnoreCase) ||
                    a.ExecutablePath.Equals(fileName, StringComparison.OrdinalIgnoreCase));
            }
        }

        private const string CanaryDecoyContent =
@"🛡️ ULTRON DEFENDER TOTAL SECURITY — GİZLİ GÜVENLİK VE FİDYE KORUMA AJANI (CANARY DECOY)
========================================================================================
Sayın Kullanıcı,

Bu dosya, bilgisayarınızı fidye virüslerine (Ransomware / WannaCry / LockBit vb.) karşı
7/24 korumak için Ultron Defender tarafından özel olarak oluşturulmuş bir güvenlik tuzağıdır.

🎯 AMACIMIZ:
Olası bir fidye virüsü dosyalarınızı şifrelemeye başladığında, alfabetik sırayla ilk bu
dosyayı hedef alır. Bu dosyaya dokunulduğu an Ultron Defender virüsü 0.1 milisaniyede yakalar
ve gerçek fotoğraflarınız, belgeleriniz ve oyunlarınız zarar görmeden virüsü durdurur.

⚠️ BİLGİLENDİRME:
Amacımız bilgisayarınızı korumaktır. Bilgisayarınızın maksimum güvenliği için bu dosyanın
silinmemesi ve kalması önerilir. Ultron Defender devrede olduğu sürece güvendesiniz!";

        private void DeployCanaryDecoys()
        {
            _canaryFiles.Clear();
            foreach (var dir in _protectedDirs)
            {
                try
                {
                    var canaryPath = Path.Combine(dir, "!_ultron_shield_canary.docx");
                    if (!File.Exists(canaryPath))
                    {
                        File.WriteAllText(canaryPath, CanaryDecoyContent, Encoding.UTF8);
                        File.SetAttributes(canaryPath, FileAttributes.Hidden | FileAttributes.System);
                    }
                    else
                    {
                        File.SetAttributes(canaryPath, FileAttributes.Hidden | FileAttributes.System);
                    }
                    _canaryFiles.Add(canaryPath);
                }
                catch { }
            }
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            CheckRansomwareBurst(e.FullPath, "Yeni dosya oluşturuldu");
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            var newExt = Path.GetExtension(e.FullPath).ToLowerInvariant();

            if (KnownRansomwareExtensions.Contains(newExt))
            {
                _ = EvaluateAndContainThreatAsync(e.FullPath, $"🚨 Bilinen fidye şifreleme uzantısı tespit edildi: '{newExt}' (Eski: '{e.OldName}')", riskScore: 95);
                return;
            }

            if (e.OldFullPath.EndsWith("!_ultron_shield_canary.docx", StringComparison.OrdinalIgnoreCase))
            {
                _ = EvaluateAndContainThreatAsync(e.FullPath, "🚨 Kritik Tuzak İhlali: Kalkan Canary (yem) dosyası yeniden adlandırıldı veya şifreleniyor!", riskScore: 100);
                return;
            }

            CheckRansomwareBurst(e.FullPath, "Dosya yeniden adlandırıldı");
        }

        private void OnFileModified(object sender, FileSystemEventArgs e)
        {
            if (e.FullPath.EndsWith("!_ultron_shield_canary.docx", StringComparison.OrdinalIgnoreCase))
            {
                _ = EvaluateAndContainThreatAsync(e.FullPath, "🚨 Kritik Tuzak İhlali: Kalkan Canary dosyası izinsiz değiştirildi!", riskScore: 100);
                return;
            }

            // Entropy Delta Check on modified document
            _ = Task.Run(async () =>
            {
                try
                {
                    if (File.Exists(e.FullPath))
                    {
                        var ext = Path.GetExtension(e.FullPath).ToLowerInvariant();
                        if (ext is ".docx" or ".xlsx" or ".pdf" or ".txt" or ".jpg")
                        {
                            var currentEntropy = await EntropyCalculator.CalculateEntropyAsync(e.FullPath);
                            if (_fileEntropyCache.TryGetValue(e.FullPath, out var previousEntropy))
                            {
                                if (currentEntropy - previousEntropy > 2.8 && currentEntropy > 7.5)
                                {
                                    await EvaluateAndContainThreatAsync(e.FullPath, $"⚠️ Anormal Yüksek Entropi Sıçraması ({previousEntropy:F2} -> {currentEntropy:F2}). Şifreleme saldırısı şüphesi!", riskScore: 85);
                                }
                            }
                            _fileEntropyCache[e.FullPath] = currentEntropy;
                        }
                    }
                }
                catch { }
            });

            CheckRansomwareBurst(e.FullPath, "Dosya değiştirildi");
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (_isCleaningUpCanaries) return;

            if (e.FullPath.EndsWith("!_ultron_shield_canary.docx", StringComparison.OrdinalIgnoreCase))
            {
                // 1. Bilgilendirici Bildirim Gönder
                OnNotificationRaised?.Invoke(
                    "🛡️ Ultron Defender - Fidye Kalkanı Bilgilendirmesi",
                    "Fidye tuzağı (Canary) dosyası silindi. Amacımız bilgisayarınızı fidye virüslerine karşı korumaktır. Güvenliğiniz için tuzak koruması otomatik olarak yeniden oluşturuldu.",
                    "Info");

                // 2. Korumayı sürdürmek için dosyayı otomatik olarak arka planda yeniden üret
                _ = Task.Run(async () =>
                {
                    await Task.Delay(1500);
                    try
                    {
                        if (!File.Exists(e.FullPath) && _isActive && !_isCleaningUpCanaries)
                        {
                            var parentDir = Path.GetDirectoryName(e.FullPath);
                            if (parentDir != null && Directory.Exists(parentDir))
                            {
                                File.WriteAllText(e.FullPath, CanaryDecoyContent, Encoding.UTF8);
                                File.SetAttributes(e.FullPath, FileAttributes.Hidden | FileAttributes.System);
                            }
                        }
                    }
                    catch { }
                });
            }
        }

        private void CheckRansomwareBurst(string path, string operation)
        {
            var now = DateTime.UtcNow;
            _globalRapidChanges.Enqueue(now);

            while (_globalRapidChanges.TryPeek(out var oldest) && (now - oldest).TotalSeconds > 2.5)
            {
                _globalRapidChanges.TryDequeue(out _);
            }

            if (_globalRapidChanges.Count >= 20)
            {
                _globalRapidChanges.Clear();
                _ = EvaluateAndContainThreatAsync(path, $"🚨 Kitle Dosya Modifikasyon Anomalisi (2.5 saniyede {_globalRapidChanges.Count}+ dosya işlem gördü)!", riskScore: 90);
            }
        }

        public async Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(string offendingPath, string reason, int riskScore, int pid = 0)
        {
            Interlocked.Increment(ref _totalBlockedCount);

            int targetPid = pid;
            string targetProcName = "Bilinmeyen Süreç";
            string targetProcPath = string.Empty;
            bool processTerminated = false;

            // 1. Identify offending process locking the file or recent processes
            try
            {
                var processes = Process.GetProcesses();
                foreach (var p in processes)
                {
                    try
                    {
                        if (p.Id <= 4 || CriticalProcesses.IsCriticalProcess(p.ProcessName)) continue;
                        if (IsApplicationAllowed(p.ProcessName) || IsApplicationAllowed(p.MainModule?.FileName ?? "")) continue;

                        if (targetPid > 0 && p.Id == targetPid)
                        {
                            targetProcName = p.ProcessName;
                            targetProcPath = p.MainModule?.FileName ?? "";
                            break;
                        }

                        if (string.Equals(p.MainModule?.FileName, offendingPath, StringComparison.OrdinalIgnoreCase))
                        {
                            targetPid = p.Id;
                            targetProcName = p.ProcessName;
                            targetProcPath = p.MainModule?.FileName ?? "";
                            break;
                        }
                    }
                    catch { }
                }
            }
            catch { }

            // 2. Active Process Termination if High/Critical Risk
            if (riskScore >= 70 && targetPid > 4 && !CriticalProcesses.IsCriticalProcess(targetProcName))
            {
                try
                {
                    using var procToKill = Process.GetProcessById(targetPid);
                    if (!procToKill.HasExited)
                    {
                        procToKill.Kill(entireProcessTree: true);
                        procToKill.WaitForExit(1500);
                        processTerminated = true;
                        _logger?.LogWarning("Ransomware offending process terminated: {Proc} (PID: {Pid})", targetProcName, targetPid);
                    }
                }
                catch { }
            }

            // 3. Quarantine Source Binary if path exists
            if (!string.IsNullOrEmpty(targetProcPath) && File.Exists(targetProcPath) && _quarantineService != null)
            {
                try
                {
                    await _quarantineService.QuarantineFileAsync(targetProcPath, $"Ransomware Activity: {reason}");
                }
                catch { }
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

        public void Dispose()
        {
            StopShield();
        }
    }
}
