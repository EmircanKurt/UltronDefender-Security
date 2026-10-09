using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Recommendations.Engine;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;

namespace AegisPC.App.ViewModels
{
    public partial class DashboardViewModel : ObservableObject, IDisposable
    {
        public void Dispose()
        {
            _threatNotificationTimer?.Dispose();
            _uptimeTimer?.Dispose();
            _dailyStatsDebounceTimer?.Dispose();
            _protectionHealthTimer?.Dispose();
            if (_ipcClient != null) _ipcClient.StatusChanged -= OnServiceStatusChanged;
            if (_ipcClient is AegisPC.ServiceContracts.IDeviceNoticeClient devices) devices.DeviceObserved -= OnDeviceObserved;
        }
        private readonly IPerformanceMonitor? _performanceMonitor;
        private readonly IProcessMonitor? _processMonitor;
        private readonly HealthScoringEngine? _healthScoringEngine;
        private readonly IStartupAnalyzer? _startupAnalyzer;
        private readonly ISecurityFindingService? _findingService;
        private readonly ICrashAnalyzer? _crashAnalyzer;
        private readonly AegisPC.ServiceContracts.IServiceIpcClient? _ipcClient;

        // Health Scores
        [ObservableProperty] private int overallHealthScore = 98;
        [ObservableProperty] private int securityScore = 100;
        [ObservableProperty] private int performanceScore = 95;
        [ObservableProperty] private int stabilityScore = 100;
        [ObservableProperty] private int startupScore = 95;
        [ObservableProperty] private int browserSecurityScore = 100;

        // Telemetry & 4 Live Enterprise Badges (Real-Data Driven)
        [ObservableProperty] private double cpuUsage = 0.0;
        [ObservableProperty] private double memoryUsage = 0.0;
        [ObservableProperty] private double diskUsage = 0.0;
        [ObservableProperty] private double networkUsage = 0.0;
        [ObservableProperty] private int activeProcessCount = 0;
        [ObservableProperty] private int startupAppCount = 0;
        [ObservableProperty] private string lastScanTime = "Henüz yapılmadı";
        [ObservableProperty] private int pendingFindingsCount = 0;
        [ObservableProperty] private int recentCrashCount = 0;

        // 1. Bugün Taranan Dosya Sayısı
        [ObservableProperty] private int filesScannedCount = 0;
        // 2. Bu Ay Engellenen Tehdit Sayısı
        [ObservableProperty] private int threatsBlockedThisMonth = 0;
        // 3. Son Veritabanı Güncellemesi
        [ObservableProperty] private string lastDatabaseUpdateFormatted = "Bugün";
        // 4. Koruma Süresi (Live Uptime)
        [ObservableProperty] private string protectionUptimeText = "0 sn";

        // Status Banner Hero
        [ObservableProperty] private string shortSummary = "Koruma kapsamı ve hizmet bağlantısı doğrulanıyor.";
        [ObservableProperty] private string protectionStatusText = "Koruma henüz doğrulanmadı";
        [ObservableProperty] private string protectionBadgeText = "Hizmet durumunu bekliyor";
        [ObservableProperty] private string protectionStatusColor = "#F5A623";
        [ObservableProperty] private string protectionStatusSymbol = "ShieldAlert24";
        [ObservableProperty] private bool hasThreatsDetected = false;
        [ObservableProperty] private string threatActionText = "Tehditleri İncele";
        [ObservableProperty] private bool isServiceConnected = false;
        [ObservableProperty] private bool isRealTimeProtectionActive = false;
        [ObservableProperty] private int threatsBocked24h = 0;
        [ObservableProperty] private string signatureDbVersion = "Güncelleme durumu doğrulanmadı";
        [ObservableProperty] private string engineArchitectureText = "Modül kapsamı doğrulanıyor";
        [ObservableProperty] private string themeButtonText = AegisPC.App.Services.AppThemeManager.IsDarkMode ? "Gündüz Modu" : "Gece Modu";

        // Interactive Feature 1: Ransomware Remediation Banner
        [ObservableProperty] private bool isRansomwareEnabled = false;
        [ObservableProperty] private bool showRansomwareDetails = false;
        [ObservableProperty] private string ransomwareActionText = "Korumalı";
        [ObservableProperty] private string ransomwareStatusText = "Açık";
        [ObservableProperty] private string ransomwareStatusColor = "#4CAF50";
        [ObservableProperty] private string ransomwareTitle = "Fidye Kalkanı Devrede (Tam Koruma)";
        [ObservableProperty] private string ransomwareDescription = "Belgelerinizi ve resimlerinizi şifreleme girişimlerine karşı korur.";

        // Interactive Feature 2: Quick Scan Live State
        [ObservableProperty] private bool isScanning = false;
        [ObservableProperty] private double scanProgress = 0.0;
        [ObservableProperty] private string scanCurrentFile = "";
        [ObservableProperty] private int scanScannedCount = 0;
        [ObservableProperty] private int scanThreatCount = 0;
        [ObservableProperty] private string quickScanButtonText = "Taramayı Başlat";

        partial void OnIsScanningChanged(bool value)
        {
            OnPropertyChanged(nameof(QuickScanCardTitle));
            OnPropertyChanged(nameof(QuickScanCardSubtitle));
        }

        public string QuickScanCardTitle => IsScanning ? "Taramayı İzle (Çalışıyor)" : "Hızlı Tarama Başlat";
        public string QuickScanCardSubtitle => IsScanning ? "Devam eden aktif virüs taramasını ve bulunan tehditleri görüntüle" : "Kritik sistem dizinlerini, belleği ve başlangıç dosyalarını tara";



        // Interactive Feature 4: Device Modal
        [ObservableProperty] private bool showDeviceModal = false;



        // Interactive Feature 6: Quick Action Selector Modal (+)
        [ObservableProperty] private bool showQuickActionModal = false;

        // Interactive Feature 7: Toast Notification System
        [ObservableProperty] private bool showToast = false;
        [ObservableProperty] private string toastMessage = "";
        [ObservableProperty] private string toastType = "Success"; // Success, Info, Warning

        // Real-Time Protection Live Activity Telemetry
        public System.Collections.ObjectModel.ObservableCollection<AegisPC.Security.RealTime.RealTimeActivityEvent> LiveActivities { get; } = new();
        public System.Collections.ObjectModel.ObservableCollection<string> WatchedLocationsList { get; } = new();
        [ObservableProperty] private string realTimeHealthStatus = "Doğrulanmadı";
        [ObservableProperty] private string realTimeHealthMessage = "Koruma hizmetinden güncel durum bekleniyor";
        [ObservableProperty] private string realTimeHealthColor = "#F5A623";
        [ObservableProperty] private string watcherStatusText = "Doğrulanmadı";
        [ObservableProperty] private string scannerStatusText = "Doğrulanmadı";
        [ObservableProperty] private string quarantineStatusText = "Hizmet gerekli";
        [ObservableProperty] private string eventQueueStatusText = "Doğrulanmadı";
        [ObservableProperty] private string lastEventTimeAgo = "Henüz olay yok";

        // Startup Security Sweep Live State
        public System.Collections.ObjectModel.ObservableCollection<AegisPC.Contracts.Services.StartupSweepFinding> StartupSweepFindings { get; } = new();
        [ObservableProperty] private string startupSweepStatusText = "Açılış taraması kapalı";
        [ObservableProperty] private string startupSweepBadgeColor = "#8C9198";
        [ObservableProperty] private string startupSweepFilesRatio = "0 / 0";
        [ObservableProperty] private double startupSweepProgressPercent = 0.0;
        [ObservableProperty] private string startupSweepCurrentFile = "";
        [ObservableProperty] private int startupSweepThreatsCount = 0;
        [ObservableProperty] private int startupSweepSuspiciousCount = 0;
        [ObservableProperty] private int startupSweepCleanCount = 0;
        [ObservableProperty] private bool isStartupSweepRunning = false;

        // Threat Detail Modal State
        [ObservableProperty] private bool showThreatDetailModal = false;
        [ObservableProperty] private AegisPC.Contracts.Services.StartupSweepFinding? selectedThreatFinding;

        private readonly IScanCoordinatorService? _scanCoordinator;
        private readonly AegisPC.Security.RealTime.IRealTimeProtectionEngine? _realTimeEngine;
        private readonly AegisPC.Contracts.Services.IStartupSecuritySweepService? _startupSweepService;
        private readonly IQuarantineService? _quarantineService;
        private readonly AegisPC.Security.RealTime.IRansomwareProtectionEngine? _ransomwareEngine;
        private readonly AegisPC.Infrastructure.Configuration.SettingsService? _settingsService;

        public static DashboardViewModel? Current { get; private set; }

        public DashboardViewModel(
            IPerformanceMonitor? performanceMonitor = null,
            IProcessMonitor? processMonitor = null,
            HealthScoringEngine? healthScoringEngine = null,
            IStartupAnalyzer? startupAnalyzer = null,
            ISecurityFindingService? findingService = null,
            ICrashAnalyzer? crashAnalyzer = null,
            IFileScanner? fileScanner = null,
            IScanCoordinatorService? scanCoordinator = null,
            AegisPC.ServiceContracts.IServiceIpcClient? ipcClient = null,
            AegisPC.Security.RealTime.IRealTimeProtectionEngine? realTimeEngine = null,
            AegisPC.Contracts.Services.IStartupSecuritySweepService? startupSweepService = null,
            IQuarantineService? quarantineService = null,
            AegisPC.Security.RealTime.IRansomwareProtectionEngine? ransomwareEngine = null,
            AegisPC.Infrastructure.Configuration.SettingsService? settingsService = null)
        {
            _performanceMonitor = performanceMonitor;
            _processMonitor = processMonitor;
            _healthScoringEngine = healthScoringEngine;
            _startupAnalyzer = startupAnalyzer;
            _findingService = findingService;
            _crashAnalyzer = crashAnalyzer;
            _scanCoordinator = scanCoordinator;
            _ipcClient = ipcClient;
            _realTimeEngine = realTimeEngine;
            _startupSweepService = startupSweepService;
            _quarantineService = quarantineService;
            _ransomwareEngine = ransomwareEngine;
            _settingsService = settingsService;
            Current = this;

            // A desired local setting is not observed SYSTEM-service state. Never start a UI-owned shield.
            isRansomwareEnabled = false;
            UpdateRansomwareStateTexts(false);

            if (_startupSweepService != null)
            {
                _startupSweepService.OnProgressChanged += (p) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        if (p.Status == StartupSweepStatus.Preparing)
                            StartupSweepFindings.Clear();
                        IsStartupSweepRunning = p.Status == StartupSweepStatus.Scanning || p.Status == StartupSweepStatus.Preparing;
                        StartupSweepStatusText = p.Status switch
                        {
                            StartupSweepStatus.Preparing => "Hazırlanıyor",
                            StartupSweepStatus.Scanning => "Taranıyor...",
                            StartupSweepStatus.ThreatsFound => "Doğrulanmış bulgu var",
                            StartupSweepStatus.Clean => "İncelenen içerikte bulgu yok",
                            StartupSweepStatus.Completed when p.SuspiciousFound > 0 => "İnceleme bekleyen bulgu var",
                            StartupSweepStatus.Completed => "Tarama tamamlandı",
                            StartupSweepStatus.Failed => "Tarama tamamlanamadı",
                            StartupSweepStatus.Cancelled => "Tarama iptal edildi",
                            _ => "Hazır"
                        };
                        StartupSweepBadgeColor = p.Status switch
                        {
                            StartupSweepStatus.ThreatsFound => "#C41E1E",
                            StartupSweepStatus.Scanning => "#2196F3",
                            StartupSweepStatus.Preparing => "#F5A623",
                            StartupSweepStatus.Failed or StartupSweepStatus.Cancelled => "#F5A623",
                            StartupSweepStatus.Completed when p.SuspiciousFound > 0 => "#F5A623",
                            _ => "#4CAF50"
                        };
                        StartupSweepFilesRatio = $"{p.ScannedFiles:N0} / {p.TotalFiles:N0}";
                        StartupSweepProgressPercent = p.ProgressPercent;
                        StartupSweepCurrentFile = p.CurrentFile;
                        StartupSweepThreatsCount = p.ThreatsFound;
                        StartupSweepSuspiciousCount = p.SuspiciousFound;
                        StartupSweepCleanCount = p.CleanFiles;

                        if (p.ScannedFiles > 0)
                        {
                            IncrementDailyScanned(1);
                        }
                    });
                };

                _startupSweepService.OnThreatDiscovered += (f) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        StartupSweepFindings.Insert(0, f);
                        if (f.IsQuarantined)
                        {
                            ThreatsBocked24h++;
                            ThreatsBlockedThisMonth++;
                        }
                        HasThreatsDetected = true;
                        ProtectionStatusText = f.IsQuarantined ? "Dosya karantinaya alındı" : "Güvenlik bulgusu incelenmeli";
                        ProtectionBadgeText = $"{f.FileName} ({f.Verdict})";
                        ProtectionStatusColor = "#C41E1E";
                        ProtectionStatusSymbol = "ShieldAlert24";

                        LiveActivities.Insert(0, new AegisPC.Security.RealTime.RealTimeActivityEvent
                        {
                            Timestamp = DateTime.Now,
                            FileName = f.FileName,
                            FilePath = f.FilePath,
                            Stage = "Başlangıç Taraması",
                            Message = f.FilePath,
                            RiskScore = f.RiskScore,
                            Verdict = f.Verdict,
                            Action = f.IsQuarantined ? "QUARANTINED" : f.Action ?? "WARN",
                            Severity = f.IsQuarantined ? "Danger" : "Warning"
                        });
                        while (LiveActivities.Count > 15) LiveActivities.RemoveAt(LiveActivities.Count - 1);

                        TriggerThreatToast(f.FileName, isQuarantined: f.IsQuarantined);
                    });
                };

                _startupSweepService.OnSweepCompleted += (res) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(async () =>
                    {
                        IsStartupSweepRunning = false;
                        StartupSweepFindings.Clear();
                        foreach (var finding in res.Findings
                            .Where(f => f.Action != "ALLOW")
                            .OrderByDescending(f => f.DetectionTime))
                            StartupSweepFindings.Add(finding);
                        (StartupSweepStatusText, StartupSweepBadgeColor) = GetStartupSweepSummary(res);
                        _ = RefreshMonthlyQuarantineCountAsync();
                        await RefreshThreatStatusAsync();
                    });
                };

                // Opening the UI never schedules a sweep. RT and service-owned idle work are independent.
            }

            if (_realTimeEngine != null)
            {
                _realTimeEngine.OnActivityLogged += (act) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        LiveActivities.Insert(0, act);
                        while (LiveActivities.Count > 15) LiveActivities.RemoveAt(LiveActivities.Count - 1);

                        IncrementDailyScanned(1);
                        LastEventTimeAgo = $"{DateTime.Now:HH:mm:ss}";
                        if (act.Action == "QUARANTINED")
                        {
                            ThreatsBocked24h++;
                            ThreatsBlockedThisMonth++;
                            HasThreatsDetected = true;
                            ProtectionStatusText = "Tehdit engellendi";
                            ProtectionBadgeText = $"{act.FileName} karantinaya alındı";
                            ProtectionStatusColor = "#C41E1E";
                            ProtectionStatusSymbol = "ShieldAlert24";
                            TriggerThreatToast(act.FileName, isQuarantined: true);
                        }
                        else if (act.Action == "WARN" || act.Severity == "Warning" || act.Severity == "Danger")
                        {
                            ProtectionStatusText = "Şüpheli aktivite algılandı";
                            ProtectionBadgeText = $"{act.FileName} incelendi";
                            ProtectionStatusColor = "#F5A623";
                            ProtectionStatusSymbol = "Warning24";
                            TriggerThreatToast(act.FileName, isQuarantined: false);
                        }
                    });
                };

                // Local read-only scan telemetry must not overwrite service-owned protection health.
            }

            if (_scanCoordinator != null)
            {
                _scanCoordinator.ProgressChanged += (p) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        IsScanning = true;
                        ScanProgress = p.ProgressPercent;
                        ScanCurrentFile = p.CurrentFile;
                        ScanScannedCount = p.ScannedFiles;
                        ScanThreatCount = p.FindingsCount;
                        QuickScanButtonText = "Durdur";
                        ProtectionStatusText = "Sistem taranıyor...";
                        string scanTypeName = p.ScanType == AegisPC.Core.Enums.ScanType.Full ? "Tam tarama" :
                                              p.ScanType == AegisPC.Core.Enums.ScanType.Custom ? "Özel tarama" : "Hızlı tarama";
                        ProtectionBadgeText = $"{scanTypeName} çalışıyor";
                        ProtectionStatusColor = "#2196F3";
                    });
                };

                _scanCoordinator.ScanCompleted += (result) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(async () =>
                    {
                        IsScanning = false;
                        ScanProgress = result.Status == AegisPC.Core.Enums.ScanStatus.Completed ? 100 : Math.Min(99, ScanProgress);
                        LastScanTime = result.Status == AegisPC.Core.Enums.ScanStatus.Completed ? "Az önce" : "Son tarama tamamlanmadı";
                        IncrementDailyScanned(result.ScannedFiles);
                        QuickScanButtonText = "Tekrar Tara";

                        int activeFindingsCount = result.Findings?.Count(f => f.Status == AegisPC.Core.Enums.FindingStatus.Active && !f.IsAllowlisted) ?? 0;
                        PendingFindingsCount = activeFindingsCount;

                        if (result.Status != AegisPC.Core.Enums.ScanStatus.Completed)
                        {
                            HasThreatsDetected = activeFindingsCount > 0;
                            ProtectionStatusText = result.Status == AegisPC.Core.Enums.ScanStatus.Cancelled ? "Tarama iptal edildi" : "Tarama tamamlanamadı";
                            ProtectionBadgeText = $"{activeFindingsCount} inceleme bekleyen bulgu; kapsam tamamlanmadı";
                            ProtectionStatusColor = "#F5A623";
                            ProtectionStatusSymbol = "Warning24";
                            TriggerToast("Tarama tamamlanmadı. İncelenemeyen dosyalar temiz ilan edilmedi; ayrıntıları Tarayıcı bölümünden kontrol edin.", "Warning");
                        }
                        else if (activeFindingsCount > 0)
                        {
                            HasThreatsDetected = true;
                            ProtectionStatusText = "İnceleme bekleyen bulgular var";
                            ProtectionBadgeText = $"{activeFindingsCount} güvenlik bulgusu";
                            ProtectionStatusColor = "#C41E1E";
                            ProtectionStatusSymbol = "ShieldAlert24";
                            TriggerToast($"Tarama tamamlandı: {activeFindingsCount} inceleme bekleyen güvenlik bulgusu. Bu sayı doğrulanmış virüs sayısı değildir.", "Warning");
                        }
                        else
                        {
                            HasThreatsDetected = false;
                            bool incompleteCoverage = result.FailedFiles > 0 || result.TimedOutFiles > 0;
                            ProtectionStatusText = incompleteCoverage ? "Tarama kapsamı eksik" : "İncelenen içerikte aktif bulgu yok";
                            ProtectionBadgeText = incompleteCoverage ? "İncelenemeyen dosyalar temiz sayılmadı" : "Tarama sonucu; koruma durumu ayrı doğrulanır";
                            ProtectionStatusColor = incompleteCoverage ? "#F5A623" : "#4CAF50";
                            ProtectionStatusSymbol = incompleteCoverage ? "Warning24" : "ShieldCheckmark24";
                            TriggerToast($"Tarama tamamlandı: {result.ScannedFiles:N0} dosya incelendi, aktif bulgu yok. {result.FailedFiles} hata, {result.TimedOutFiles} zaman aşımı.", incompleteCoverage ? "Warning" : "Success");
                        }

                        _ = RefreshMonthlyQuarantineCountAsync();
                        await RefreshThreatStatusAsync();
                    });
                };

                // Sync current state if a scan was already running in background
                if (_scanCoordinator.IsScanning)
                {
                    IsScanning = true;
                    ScanProgress = _scanCoordinator.ProgressPercent;
                    ScanCurrentFile = _scanCoordinator.CurrentFile;
                    ScanScannedCount = _scanCoordinator.ScannedFiles;
                    ScanThreatCount = _scanCoordinator.FindingsCount;
                    QuickScanButtonText = "Durdur";
                    ProtectionStatusText = "Sistem taranıyor...";
                    string scanTypeName = _scanCoordinator.CurrentScanType == AegisPC.Core.Enums.ScanType.Full ? "Tam tarama" :
                                          _scanCoordinator.CurrentScanType == AegisPC.Core.Enums.ScanType.Custom ? "Özel tarama" : "Hızlı tarama";
                    ProtectionBadgeText = $"{scanTypeName} çalışıyor";
                    ProtectionStatusColor = "#2196F3";
                }
            }

            if (_ipcClient != null)
            {
            _ipcClient.StatusChanged += OnServiceStatusChanged;
            if (_ipcClient is AegisPC.ServiceContracts.IDeviceNoticeClient devices) devices.DeviceObserved += OnDeviceObserved;
            }
            _protectionHealthTimer = new Timer(_ => CheckProtectionFreshness(), null,
                TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));

            if (_performanceMonitor != null)
            {
                _performanceMonitor.OnSampleCollected += OnPerformanceSampleCollected;
                _ = _performanceMonitor.StartMonitoringAsync();
            }

            // Start live protection uptime timer (updates every second)
            _uptimeTimer = new System.Threading.Timer(_ => UpdateProtectionUptime(), null, TimeSpan.Zero, TimeSpan.FromSeconds(1));

            // Arka planda donma yapmadan verileri yükle
            Task.Run(async () => 
            {
                try
                {
                    await LoadDashboardDataAsync();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine(ex);
                }
            });
        }

        partial void OnIsRansomwareEnabledChanged(bool value)
        {
            if (_applyingServiceStatus) return;
            _ = RequestProtectionCommandAsync(value
                ? AegisPC.ServiceContracts.IpcMessages.ServiceCommandType.EnableRansomwareShield
                : AegisPC.ServiceContracts.IpcMessages.ServiceCommandType.DisableRansomwareShield, value);
        }

        private void UpdateRansomwareStateTexts(bool active)
        {
            if (active)
            {
                RansomwareStatusText = "Açık";
                RansomwareActionText = "Korumalı";
                RansomwareStatusColor = "#4CAF50";
                RansomwareTitle = "Fidye gözlemi hizmette etkin";
                RansomwareDescription = "Kullanıcı modu gözlemi; zarar oluşmadan engelleme garantisi değildir.";
            }
            else
            {
                RansomwareStatusText = "Kapalı";
                RansomwareActionText = "Devre Dışı";
                RansomwareStatusColor = "#94A3B8";
                RansomwareTitle = "Fidye Kalkanı Kapalı";
                RansomwareDescription = "Belgelerinizi ve resimlerinizi şifreleme girişimlerine karşı korur.";
            }
        }

        /// <summary>
        /// Sistemdeki aktif ve çözülmemiş tehditleri denetleyerek ana ekran uyarı durumunu (banner) senkronize eder.
        /// Çözülen veya temizlenen tehditler sonrası kırmızı uyarı bandını kapatır.
        /// </summary>
        public async Task RefreshThreatStatusAsync()
        {
            try
            {
                int activeScanFindings = 0;
                if (_scanCoordinator?.CurrentFindings != null)
                {
                    activeScanFindings = _scanCoordinator.CurrentFindings.Count(f => f.Status == AegisPC.Core.Enums.FindingStatus.Active && !f.IsAllowlisted && AegisPC.Core.Models.FindingVisibilityPolicy.IsSecurityConcern(f));
                }

                int activeServiceFindings = 0;
                if (_findingService != null)
                {
                    try
                    {
                        activeServiceFindings = (await _findingService.GetAllFindingsAsync()).Count(f => f.Status == AegisPC.Core.Enums.FindingStatus.Active && !f.IsAllowlisted && AegisPC.Core.Models.FindingVisibilityPolicy.IsSecurityConcern(f));
                    }
                    catch { }
                }

                int activeSweepFindings = 0;
                if (StartupSweepFindings != null)
                {
                    activeSweepFindings = StartupSweepFindings.Count(f => !f.IsQuarantined &&
                        (f.Action == "WARN" || f.Action == "REVIEW_REQUIRED" || f.Action == "QUARANTINE_FAILED"));
                }

                int totalActiveThreats = Math.Max(activeScanFindings, Math.Max(activeServiceFindings, activeSweepFindings));
                bool startupIncomplete = _startupSweepService?.LastResult?.FinalStatus is StartupSweepStatus.Failed or StartupSweepStatus.Cancelled;

                void ApplyStatus()
                {
                    if (totalActiveThreats > 0)
                    {
                        HasThreatsDetected = true;
                        ProtectionStatusText = "Güvenlik bulgusu bulundu";
                        ProtectionBadgeText = startupIncomplete
                            ? $"{totalActiveThreats} inceleme bekleyen bulgu; tarama eksik"
                            : $"{totalActiveThreats} inceleme bekleyen bulgu";
                        ProtectionStatusColor = "#C41E1E";
                        ProtectionStatusSymbol = "ShieldAlert24";
                        PendingFindingsCount = totalActiveThreats;
                    }
                    else if (startupIncomplete)
                    {
                        HasThreatsDetected = false;
                        ProtectionStatusText = "Başlangıç taraması tamamlanamadı";
                        ProtectionBadgeText = "İncelenemeyen dosyalar temiz sayılmadı";
                        ProtectionStatusColor = "#F5A623";
                        ProtectionStatusSymbol = "Warning24";
                        PendingFindingsCount = 0;
                    }
                    else
                    {
                        HasThreatsDetected = false;
                        ProtectionStatusText = "İncelenen içerikte aktif bulgu yok";
                        ProtectionBadgeText = "Koruma durumu ayrıca doğrulanır";
                        ProtectionStatusColor = IsRealTimeProtectionActive ? "#4CAF50" : "#F5A623";
                        ProtectionStatusSymbol = IsRealTimeProtectionActive ? "ShieldCheckmark24" : "ShieldAlert24";
                        PendingFindingsCount = 0;
                    }
                }

                if (Application.Current?.Dispatcher != null && !Application.Current.Dispatcher.CheckAccess())
                {
                    await Application.Current.Dispatcher.InvokeAsync(ApplyStatus);
                }
                else
                {
                    ApplyStatus();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine(ex);
            }
        }

        private static (string Text, string Color) GetStartupSweepSummary(StartupSweepResult result) =>
            result.FinalStatus switch
            {
                StartupSweepStatus.Busy => ("Başka tarama sürüyor; başlangıç kontrolü yapılmadı", "#F5A623"),
                StartupSweepStatus.Failed => ($"Tarama tamamlanamadı ({result.IncompleteCount} incelenemedi)", "#F5A623"),
                StartupSweepStatus.Cancelled => ("Tarama iptal edildi", "#F5A623"),
                StartupSweepStatus.ThreatsFound => ($"{result.ThreatsCount} doğrulanmış bulgu", "#C41E1E"),
                StartupSweepStatus.Completed when result.IncompleteCount > 0 =>
                    ($"Tarama bitti; {result.IncompleteCount} dosyanın incelemesi eksik, {result.SuspiciousCount} inceleme bekleyen bulgu", "#F5A623"),
                StartupSweepStatus.Completed when result.SuspiciousCount > 0 =>
                    ($"{result.SuspiciousCount} inceleme bekleyen bulgu", "#F5A623"),
                StartupSweepStatus.Clean => ("İncelenen içerikte bulgu yok", "#4CAF50"),
                _ => ("Tarama durumu bilinmiyor", "#F5A623")
            };
    }
}
