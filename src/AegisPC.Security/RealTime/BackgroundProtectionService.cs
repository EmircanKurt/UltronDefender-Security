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
        void SetScheduledScansEnabled(bool enabled);
        void NotifyScheduledScanCompleted(ScanResult result);
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
    /// Tekil gerçek zamanlı izleyiciyi tamamlayan 20 dakikalık hızlı tarama ve günlük
    /// tam tarama zamanlayıcısı. Dosya olaylarını RealTimeProtectionEngine sahiplenir.
    /// </summary>
    public class BackgroundProtectionService : IBackgroundProtectionService
    {
        private static readonly ConcurrentDictionary<string, bool> _ignoredWatchlist = new(StringComparer.OrdinalIgnoreCase);
        private static int _isAutomaticScanInProgress;

        /// <summary>
        /// Otomatik (zamanlanmış) tarama sürüyor mu? App.xaml.cs ScanCompleted bildirimi bu bayrakla susturulur.
        /// </summary>
        public static bool IsAutomaticScanInProgress
        {
            get => Volatile.Read(ref _isAutomaticScanInProgress) == 1;
            private set => Volatile.Write(ref _isAutomaticScanInProgress, value ? 1 : 0);
        }

        // Zaten bildirilmiş bulgu yolları: aynı statik bulgu her 20 dakikalık taramada tekrar bildirilmez
        private static readonly ConcurrentDictionary<string, byte> _notifiedFindingPaths = new(StringComparer.OrdinalIgnoreCase);

        private static string BuildFindingNotificationKey(SecurityFinding finding)
        {
            if (finding == null) return string.Empty;

            var basePath = !string.IsNullOrWhiteSpace(finding.ObjectPath)
                ? finding.ObjectPath.Trim()
                : finding.ObjectName.Trim();

            if (string.IsNullOrWhiteSpace(basePath))
            {
                return string.Empty;
            }

            if (!string.IsNullOrWhiteSpace(finding.SHA256))
            {
                return $"{basePath}|{finding.SHA256.Trim()}";
            }

            return $"{basePath}|{finding.Title}|{(int)finding.RiskLevel}|{finding.Category}";
        }

        private int CountNewNotificationKeys(IEnumerable<SecurityFinding> findings)
        {
            int newCount = 0;
            foreach (var finding in findings)
            {
                var key = BuildFindingNotificationKey(finding);
                if (!string.IsNullOrWhiteSpace(key) && _notifiedFindingPaths.TryAdd(key, 0))
                {
                    newCount++;
                    OnThreatDetected?.Invoke(finding);
                }
            }

            return newCount;
        }

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

        private readonly IScanCoordinatorService _scanCoordinator;
        private readonly ISettingsService? _settingsService;
        private readonly ILogger<BackgroundProtectionService>? _logger;
        private readonly bool _internalSchedulingEnabled;

        private System.Threading.Timer? _quickScanTimer;
        private System.Threading.Timer? _dailyFullScanCheckerTimer;
        private bool _isActive;
        private readonly object _lock = new();

        private readonly string _scheduleFilePath;
        private ScanScheduleState _scheduleState = new();

        public bool IsProtectionActive => _isActive;
        public event Action<SecurityFinding>? OnThreatDetected;
        public event Action<string, string>? OnNotificationRaised;

        public BackgroundProtectionService(
            IFileScanner fileScanner,
            ISecurityFindingService findingService,
            IScanCoordinatorService scanCoordinator,
            ILogger<BackgroundProtectionService>? logger = null,
            ISettingsService? settingsService = null,
            bool internalSchedulingEnabled = false)
        {
            _scanCoordinator = scanCoordinator;
            _logger = logger;
            _settingsService = settingsService;
            // The Windows service's ScanScheduler owns configured schedules. Retain
            // the legacy timers only for hosts which explicitly opt into them.
            _internalSchedulingEnabled = internalSchedulingEnabled;

            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var aegisDir = Path.Combine(appData, "AegisPC");
            _scheduleFilePath = Path.Combine(aegisDir, "scan_schedule.json");
            if (_internalSchedulingEnabled)
            {
                Directory.CreateDirectory(aegisDir);
                LoadScheduleState();
            }
        }

        public void StartProtection()
        {
            lock (_lock)
            {
                if (_isActive) return;
                _isActive = true;

                // RealTimeProtectionEngine owns file events; scheduled scans honor the user's
                // explicit schedule toggle instead of starting a surprise full scan after boot.
                if (_internalSchedulingEnabled && _settingsService?.GetSetting("ScanScheduleEnabled", false) == true)
                    StartScheduledScansInternal();
            }
        }

        public void SetScheduledScansEnabled(bool enabled)
        {
            lock (_lock)
            {
                if (!_isActive || !_internalSchedulingEnabled) return;
                if (enabled) StartScheduledScansInternal();
                else StopScheduledScansInternal();
            }
        }

        private void StartScheduledScansInternal()
        {
            if (_quickScanTimer != null || _dailyFullScanCheckerTimer != null) return;

            _quickScanTimer = new System.Threading.Timer(
                async _ => await Run20MinuteQuickScanAsync(), null,
                TimeSpan.FromMinutes(20), TimeSpan.FromMinutes(20));
            _dailyFullScanCheckerTimer = new System.Threading.Timer(
                async _ => await CheckAndRunDailyFullScanAsync(), null,
                TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(15));

            _logger?.LogInformation("Scheduled quick and daily scans enabled.");
            _ = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromSeconds(15));
                if (_isActive && _settingsService?.GetSetting("ScanScheduleEnabled", false) == true)
                    await CheckAndRunDailyFullScanAsync(isStartupCatchup: true);
            });
        }

        private void StopScheduledScansInternal()
        {
            _quickScanTimer?.Dispose();
            _quickScanTimer = null;
            _dailyFullScanCheckerTimer?.Dispose();
            _dailyFullScanCheckerTimer = null;
            _logger?.LogInformation("Scheduled scans disabled.");
        }

        public void StopProtection()
        {
            lock (_lock)
            {
                _isActive = false;
                StopScheduledScansInternal();
            }
        }

        public void NotifyScheduledScanCompleted(ScanResult result)
        {
            if (result.Status != ScanStatus.Completed) return;
            PruneNotifiedFindingPaths();
            int newCount = CountNewNotificationKeys(result.Findings);
            if (newCount > 0)
                OnNotificationRaised?.Invoke("Ultron Defender: Planlı Tarama Tamamlandı",
                    $"Planlı taramada {newCount} yeni riskli bulgu tespit edildi. Detayları Güvenlik Merkezinden inceleyebilirsiniz.");
        }

        private static void PruneNotifiedFindingPaths()
        {
            if (_notifiedFindingPaths.Count >= 10000)
            {
                _notifiedFindingPaths.Clear();
            }
        }

        private async Task Run20MinuteQuickScanAsync()
        {
            try
            {
                if (_scanCoordinator.IsScanning) return; // Skip if a scan is already actively running

                _logger?.LogInformation("Starting 20-minute periodic background quick scan...");
                IsAutomaticScanInProgress = true;
                try
                {
                    var result = await _scanCoordinator.StartScanAsync(ScanType.Quick);
                    if (result != null)
                    {
                        _scheduleState.LastQuickScanTime = DateTime.UtcNow;
                        SaveScheduleState();

                        PruneNotifiedFindingPaths();
                        // Yalnızca DAHA ÖNCE BİLDİRİLMEMİŞ bulgular için bildirim: aynı dosya/hash tekrar bildirilmez.
                        int newCount = CountNewNotificationKeys(result.Findings);

                        if (newCount > 0)
                        {
                            OnNotificationRaised?.Invoke(
                                "🚨 Ultron Defender (Antivirüs Programı): Otomatik Taramada Yeni Tehdit Bulundu!",
                                $"Arka plan taramasında {newCount} adet yeni riskli tehdit tespit edildi. Detaylar Güvenlik Merkezinde.");
                        }
                    }
                }
                finally
                {
                    IsAutomaticScanInProgress = false;
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

                IsAutomaticScanInProgress = true;
                try
                {
                    var result = await _scanCoordinator.StartScanAsync(ScanType.Full);
                    if (result != null)
                    {
                        _scheduleState.LastFullScanDate = DateTime.Today;
                        SaveScheduleState();

                        PruneNotifiedFindingPaths();
                        int newCount = CountNewNotificationKeys(result.Findings);

                        if (newCount > 0)
                        {
                            OnNotificationRaised?.Invoke(
                                "🚨 Ultron Defender (Antivirüs Programı): Günlük Tam Tarama - Yeni Tehdit Bulundu!",
                                $"Tam taramada {newCount} adet yeni şüpheli tehdit tespit edildi. Lütfen inceleyin.");
                        }
                    }
                }
                finally
                {
                    IsAutomaticScanInProgress = false;
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
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Failed to load schedule state from {Path}", _scheduleFilePath);
            }
        }

        private void SaveScheduleState()
        {
            try
            {
                var json = JsonSerializer.Serialize(_scheduleState, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_scheduleFilePath, json);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Failed to save schedule state to {Path}", _scheduleFilePath);
            }
        }
    }
}
