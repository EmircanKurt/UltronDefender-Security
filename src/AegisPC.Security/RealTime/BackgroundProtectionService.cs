using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    public interface IBackgroundProtectionService
    {
        void StartProtection();
        void StopProtection();
        bool IsProtectionActive { get; }
        event Action<SecurityFinding>? OnThreatDetected;
        event Action<string, string>? OnNotificationRaised;
    }

    public class ScanScheduleState
    {
        public DateTime? LastFullScanDate { get; set; }
        public DateTime? LastQuickScanTime { get; set; }
    }

    /// <summary>
    /// Gerçek zamanlı arka plan indirme kalkanı, 20 dakikada bir otomatik hızlı tarama
    /// ve günde 1 kez çalışan (kaçırılan günleri telafi eden) tam tarama motoru.
    /// </summary>
    public class BackgroundProtectionService : IBackgroundProtectionService
    {
        private static readonly ConcurrentDictionary<string, bool> _ignoredWatchlist = new(StringComparer.OrdinalIgnoreCase);

        public static void AddToIgnoredWatchlist(string path)
        {
            if (!string.IsNullOrEmpty(path))
            {
                _ignoredWatchlist[path] = true;
            }
        }

        public static bool IsInIgnoredWatchlist(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            return _ignoredWatchlist.ContainsKey(path);
        }

        private readonly IFileScanner _fileScanner;
        private readonly ISecurityFindingService _findingService;
        private readonly IScanCoordinatorService _scanCoordinator;
        private readonly ILogger<BackgroundProtectionService>? _logger;

        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly ConcurrentDictionary<string, DateTime> _recentlyScanned = new(StringComparer.OrdinalIgnoreCase);
        private System.Threading.Timer? _quickScanTimer;
        private System.Threading.Timer? _dailyFullScanCheckerTimer;
        private bool _isActive;
        private readonly object _lock = new();

        private readonly string _scheduleFilePath;
        private ScanScheduleState _scheduleState = new();

        public bool IsProtectionActive => _isActive;
        public event Action<SecurityFinding>? OnThreatDetected;
        public event Action<string, string>? OnNotificationRaised;

        private static readonly string[] DangerousExtensions = new[]
        {
            ".exe", ".msi", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jar", ".iso", ".zip", ".rar", ".7z"
        };

        public BackgroundProtectionService(
            IFileScanner fileScanner,
            ISecurityFindingService findingService,
            IScanCoordinatorService scanCoordinator,
            ILogger<BackgroundProtectionService>? logger = null)
        {
            _fileScanner = fileScanner;
            _findingService = findingService;
            _scanCoordinator = scanCoordinator;
            _logger = logger;

            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var aegisDir = Path.Combine(appData, "AegisPC");
            Directory.CreateDirectory(aegisDir);
            _scheduleFilePath = Path.Combine(aegisDir, "scan_schedule.json");

            LoadScheduleState();
        }

        public void StartProtection()
        {
            lock (_lock)
            {
                if (_isActive) return;
                _isActive = true;

                // 1. Setup Watchers for Desktop, Downloads, and Temp Drop Zones
                var watchPaths = new[]
                {
                    KnownPaths.Downloads,
                    KnownPaths.Temp,
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                    Path.Combine(KnownPaths.UserProfile, "Desktop"),
                    Path.Combine(KnownPaths.UserProfile, "OneDrive", "Desktop"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp")
                }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);

                foreach (var dir in watchPaths)
                {
                    try
                    {
                        var watcher = new FileSystemWatcher(dir)
                        {
                            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                            IncludeSubdirectories = false,
                            EnableRaisingEvents = true
                        };

                        watcher.Created += OnFileCreatedOrChanged;
                        watcher.Changed += OnFileCreatedOrChanged;
                        watcher.Renamed += (s, e) => OnFileCreatedOrChanged(s, new FileSystemEventArgs(WatcherChangeTypes.Created, Path.GetDirectoryName(e.FullPath) ?? "", e.Name ?? ""));

                        _watchers.Add(watcher);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "Failed to initialize watcher for {Dir}", dir);
                    }
                }

                // 2. Setup 20-Minute Periodic Background Quick Scan
                _quickScanTimer = new System.Threading.Timer(
                    async _ => await Run20MinuteQuickScanAsync(),
                    null,
                    TimeSpan.FromMinutes(20),
                    TimeSpan.FromMinutes(20));

                // 3. Daily Full Scan Checker (Checks every 15 minutes if today's full scan is done)
                _dailyFullScanCheckerTimer = new System.Threading.Timer(
                    async _ => await CheckAndRunDailyFullScanAsync(),
                    null,
                    TimeSpan.FromMinutes(1),
                    TimeSpan.FromMinutes(15));

                _logger?.LogInformation("Background protection started: Real-time download shield, 20-minute quick scan, and daily full scan active.");

                // 4. Boot-up Missed Full Scan Check (Run 15s after startup if missed today)
                Task.Run(async () =>
                {
                    await Task.Delay(15000);
                    if (_isActive)
                    {
                        await CheckAndRunDailyFullScanAsync(isStartupCatchup: true);
                    }
                });
            }
        }

        public void StopProtection()
        {
            lock (_lock)
            {
                _isActive = false;
                foreach (var w in _watchers)
                {
                    try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
                }
                _watchers.Clear();

                _quickScanTimer?.Dispose();
                _quickScanTimer = null;

                _dailyFullScanCheckerTimer?.Dispose();
                _dailyFullScanCheckerTimer = null;
            }
        }

        private async void OnFileCreatedOrChanged(object sender, FileSystemEventArgs e)
        {
            if (!FileScannerService.IsInspectableCandidate(e.FullPath)) return;

            // Debounce rapid writes
            if (_recentlyScanned.TryGetValue(e.FullPath, out var lastScanned) &&
                (DateTime.UtcNow - lastScanned).TotalSeconds < 4)
            {
                return;
            }
            _recentlyScanned[e.FullPath] = DateTime.UtcNow;

            // Wait a brief moment for file write completion / browser lock release
            await Task.Delay(500);

            try
            {
                if (!File.Exists(e.FullPath)) return;

                // Watchdog on ignored items: If an ignored file or folder creates/modifies files, trigger instant quarantine
                if (IsInIgnoredWatchlist(e.FullPath) || IsInIgnoredWatchlist(Path.GetDirectoryName(e.FullPath) ?? ""))
                {
                    var ignoredFinding = new SecurityFinding
                    {
                        ObjectPath = e.FullPath,
                        ObjectName = Path.GetFileName(e.FullPath),
                        Title = $"Göz Ardı Edilen Tehdit Eylemi: {Path.GetFileName(e.FullPath)}",
                        Description = "Bu dosya daha önce göz ardı edilmişti ancak sistemde yeni dosya/kayıt oluşturarak şüpheli faaliyette bulundu ve derhal karantinaya alındı.",
                        RiskLevel = RiskLevel.HighRisk,
                        RiskScore = 90,
                        Category = FindingCategory.MalwareSuspicion
                    };
                    OnThreatDetected?.Invoke(ignoredFinding);
                    OnNotificationRaised?.Invoke(
                        "🚨 Ultron Defender (Antivirüs Programı): Göz Ardı Edilen Tehdit Engellendi!",
                        $"Göz ardı edilen '{Path.GetFileName(e.FullPath)}' yeni bir dosya oluşturmaya çalıştı ve otomatik karantinaya kilitlendi.");
                    return;
                }

                var finding = await _fileScanner.ScanFileAsync(e.FullPath);
                if (finding != null && finding.RiskLevel >= RiskLevel.Suspicious)
                {
                    OnThreatDetected?.Invoke(finding);
                    OnNotificationRaised?.Invoke(
                        "🚨 Ultron Defender (Antivirüs Programı): Zararlı/Şüpheli Dosya Tespit Edildi!",
                        $"'{Path.GetFileName(e.FullPath)}' dosyasında güvenlik tehdidi tespit edildi (Risk: {finding.RiskScore}/100). İncelemek için tıklayın.");
                }
                // Clean files: No spam notification per master UX specification
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error during real-time scan of {Path}", e.FullPath);
            }
        }

        private async Task Run20MinuteQuickScanAsync()
        {
            try
            {
                if (_scanCoordinator.IsScanning) return; // Skip if a scan is already actively running

                _logger?.LogInformation("Starting 20-minute periodic background quick scan...");
                var result = await _scanCoordinator.StartScanAsync(ScanType.Quick);
                if (result != null)
                {
                    _scheduleState.LastQuickScanTime = DateTime.UtcNow;
                    SaveScheduleState();

                    if (result.Findings.Count > 0)
                    {
                        OnNotificationRaised?.Invoke(
                            "🚨 Ultron Defender (Antivirüs Programı): Otomatik Taramada Tehdit Bulundu!",
                            $"20 dakikalık arka plan taramasında {result.Findings.Count} adet riskli tehdit tespit edildi. Karantinaya almak için tıklayın.");
                    }
                    else
                    {
                        OnNotificationRaised?.Invoke(
                            "🛡️ Ultron Defender (Antivirüs Programı): Rutin Tarama Temiz",
                            $"20 dakikalık otomatik arka plan taraması tamamlandı ({result.ScannedFiles:N0} dosya). Sisteminiz tamamen güvende.");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "20-minute quick scan failed");
            }
        }

        private async Task CheckAndRunDailyFullScanAsync(bool isStartupCatchup = false)
        {
            try
            {
                var today = DateTime.Today;
                bool needsFullScan = _scheduleState.LastFullScanDate == null || _scheduleState.LastFullScanDate.Value.Date < today;

                if (!needsFullScan) return;
                if (_scanCoordinator.IsScanning) return;

                _logger?.LogInformation("Running Daily Full Scan (Catchup: {IsCatchup}) for date {Date}...", isStartupCatchup, today);
                
                if (isStartupCatchup)
                {
                    OnNotificationRaised?.Invoke(
                        "🛡️ Günlük Tam Tarama Başlatılıyor",
                        "Bugünkü planlanmış tam tarama henüz yapılmadığından arka planda otomatik olarak başlatılıyor...");
                }

                var result = await _scanCoordinator.StartScanAsync(ScanType.Full);
                if (result != null)
                {
                    _scheduleState.LastFullScanDate = DateTime.Today;
                    SaveScheduleState();

                    if (result.Findings.Count > 0)
                    {
                        OnNotificationRaised?.Invoke(
                            "🚨 Günlük Tam Tarama Tamamlandı - Tehdit Bulundu!",
                            $"Tam taramada {result.Findings.Count} adet şüpheli tehdit tespit edildi. Lütfen inceleyin.");
                    }
                    else
                    {
                        OnNotificationRaised?.Invoke(
                            "🛡️ Günlük Tam Tarama Tamamlandı",
                            $"Tüm sabit diskler başarıyla tarandı ({result.ScannedFiles:N0} dosya). Sisteminiz tamamen temiz.");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Daily full scan execution error");
            }
        }

        private void LoadScheduleState()
        {
            try
            {
                if (File.Exists(_scheduleFilePath))
                {
                    var json = File.ReadAllText(_scheduleFilePath);
                    var state = JsonSerializer.Deserialize<ScanScheduleState>(json);
                    if (state != null)
                    {
                        _scheduleState = state;
                    }
                }
            }
            catch { }
        }

        private void SaveScheduleState()
        {
            try
            {
                var json = JsonSerializer.Serialize(_scheduleState, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_scheduleFilePath, json);
            }
            catch { }
        }
    }
}
