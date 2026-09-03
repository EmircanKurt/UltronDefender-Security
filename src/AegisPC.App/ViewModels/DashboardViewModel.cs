using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.App.Views;
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
        [ObservableProperty] private string shortSummary = "Cihazınız ve kişisel verileriniz Ultron Defender tarafından gerçek zamanlı korunuyor.";
        [ObservableProperty] private string protectionStatusText = "GÜVENDESİNİZ";
        [ObservableProperty] private string protectionBadgeText = "GERÇEK ZAMANLI KORUMA AKTİF";
        [ObservableProperty] private string protectionStatusColor = "#4CAF50"; // Bitdefender Safe Green
        [ObservableProperty] private string protectionStatusSymbol = "ShieldCheckmark24";
        [ObservableProperty] private bool hasThreatsDetected = false;
        [ObservableProperty] private string threatActionText = "🚨 Tehditleri İncele";
        [ObservableProperty] private bool isServiceConnected = true;
        [ObservableProperty] private bool isRealTimeProtectionActive = true;
        [ObservableProperty] private int threatsBocked24h = 0;
        [ObservableProperty] private string signatureDbVersion = "v2026.08.24 (Güncel)";
        [ObservableProperty] private string engineArchitectureText = "Heuristik + AMSI + ETW Aktif";
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
        [ObservableProperty] private string quickScanButtonText = "TARAMAYI BAŞLAT";



        // Interactive Feature 4: Device & License Modal
        [ObservableProperty] private bool showDeviceModal = false;
        [ObservableProperty] private string licenseKey = "ULT-9842-X781-PRO";
        [ObservableProperty] private string licenseExpires = "365 Gün Kaldı (18.08.2027)";



        // Interactive Feature 6: Quick Action Selector Modal (+)
        [ObservableProperty] private bool showQuickActionModal = false;

        // Interactive Feature 7: Toast Notification System
        [ObservableProperty] private bool showToast = false;
        [ObservableProperty] private string toastMessage = "";
        [ObservableProperty] private string toastType = "Success"; // Success, Info, Warning

        // Real-Time Protection Live Activity Telemetry
        public System.Collections.ObjectModel.ObservableCollection<AegisPC.Security.RealTime.RealTimeActivityEvent> LiveActivities { get; } = new();
        public System.Collections.ObjectModel.ObservableCollection<string> WatchedLocationsList { get; } = new();
        [ObservableProperty] private string realTimeHealthStatus = "PROTECTED";
        [ObservableProperty] private string realTimeHealthMessage = "Tüm güvenlik modülleri aktif ve izleniyor";
        [ObservableProperty] private string realTimeHealthColor = "#35D07F";
        [ObservableProperty] private string watcherStatusText = "RUNNING";
        [ObservableProperty] private string scannerStatusText = "HEALTHY";
        [ObservableProperty] private string quarantineStatusText = "HEALTHY";
        [ObservableProperty] private string eventQueueStatusText = "HEALTHY";
        [ObservableProperty] private string lastEventTimeAgo = "Aktif";

        // Startup Security Sweep Live State
        public System.Collections.ObjectModel.ObservableCollection<AegisPC.Contracts.Services.StartupSweepFinding> StartupSweepFindings { get; } = new();
        [ObservableProperty] private string startupSweepStatusText = "TAMAMLANDI";
        [ObservableProperty] private string startupSweepBadgeColor = "#35D07F";
        [ObservableProperty] private string startupSweepFilesRatio = "0 / 0";
        [ObservableProperty] private double startupSweepProgressPercent = 100.0;
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

            // Initialize ransomware protection state
            if (_settingsService != null)
            {
                isRansomwareEnabled = _settingsService.Current.IsRansomwareShieldEnabled;
            }
            else if (_ransomwareEngine != null)
            {
                isRansomwareEnabled = _ransomwareEngine.IsShieldActive;
            }
            else
            {
                isRansomwareEnabled = true;
            }

            if (isRansomwareEnabled && _ransomwareEngine != null && !_ransomwareEngine.IsShieldActive)
            {
                try
                {
                    _ransomwareEngine.StartShield();
                }
                catch { }
            }

            UpdateRansomwareStateTexts(isRansomwareEnabled);

            if (_startupSweepService != null)
            {
                _startupSweepService.OnProgressChanged += (p) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        IsStartupSweepRunning = p.Status == StartupSweepStatus.Scanning || p.Status == StartupSweepStatus.Preparing;
                        StartupSweepStatusText = p.Status switch
                        {
                            StartupSweepStatus.Preparing => "HAZIRLANIYOR",
                            StartupSweepStatus.Scanning => "TARANIYOR...",
                            StartupSweepStatus.ThreatsFound => "TEHDİT BULUNDU",
                            StartupSweepStatus.Clean => "TEMİZ",
                            StartupSweepStatus.Completed => "TAMAMLANDI",
                            _ => "HAZIR"
                        };
                        StartupSweepBadgeColor = p.Status switch
                        {
                            StartupSweepStatus.ThreatsFound => "#C41E1E",
                            StartupSweepStatus.Scanning => "#2196F3",
                            StartupSweepStatus.Preparing => "#F5A623",
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
                        ThreatsBocked24h++;
                        ThreatsBlockedThisMonth++;
                        HasThreatsDetected = true;
                        ProtectionStatusText = "TEHDİT TESPİT EDİLDİ";
                        ProtectionBadgeText = $"🚨 {f.FileName} ({f.Verdict})";
                        ProtectionStatusColor = "#C41E1E";
                        ProtectionStatusSymbol = "ShieldAlert24";

                        LiveActivities.Insert(0, new AegisPC.Security.RealTime.RealTimeActivityEvent
                        {
                            Timestamp = DateTime.Now,
                            FileName = f.FileName,
                            FilePath = f.FilePath,
                            Stage = "BAŞLANGIÇ SÜPÜRME",
                            Message = f.FilePath,
                            RiskScore = f.RiskScore,
                            Verdict = f.Verdict,
                            Action = f.Action ?? "QUARANTINED",
                            Severity = "Danger"
                        });
                        while (LiveActivities.Count > 15) LiveActivities.RemoveAt(LiveActivities.Count - 1);

                        TriggerThreatToast(f.FileName);
                    });
                };

                _startupSweepService.OnSweepCompleted += (res) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        IsStartupSweepRunning = false;
                        StartupSweepStatusText = res.ThreatsCount > 0 ? $"{res.ThreatsCount} TEHDİT" : "TEMİZ";
                        StartupSweepBadgeColor = res.ThreatsCount > 0 ? "#C41E1E" : "#4CAF50";
                        _ = RefreshMonthlyQuarantineCountAsync();
                    });
                };

                // Launch initial non-blocking background sweep
                Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(1200);
                        await _startupSweepService.RunSweepAsync();
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Trace.WriteLine(ex);
                    }
                });
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
                        if (act.Action == "QUARANTINED" || act.Severity == "Danger")
                        {
                            ThreatsBocked24h++;
                            ThreatsBlockedThisMonth++;
                            HasThreatsDetected = true;
                            ProtectionStatusText = "TEHDİT ENGELLENDİ";
                            ProtectionBadgeText = $"🚨 {act.FileName} Karantinaya Alındı";
                            ProtectionStatusColor = "#C41E1E";
                            ProtectionStatusSymbol = "ShieldAlert24";
                            TriggerThreatToast(act.FileName);
                        }
                    });
                };

                _realTimeEngine.OnProtectionHealthChanged += (healthy, msg) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        RealTimeHealthStatus = healthy ? "PROTECTED" : "DEGRADED";
                        RealTimeHealthMessage = msg;
                        RealTimeHealthColor = healthy ? "#4CAF50" : "#C41E1E";
                        WatcherStatusText = healthy ? "RUNNING" : "DEGRADED";
                        IsRealTimeProtectionActive = healthy;
                        UpdateProtectionUptime();
                    });
                };

                // Populate watched locations
                foreach (var loc in _realTimeEngine.WatchedLocations)
                {
                    WatchedLocationsList.Add(loc);
                }
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
                        QuickScanButtonText = "DURDUR";
                        ProtectionStatusText = "SİSTEM TARANIYOR...";
                        ProtectionBadgeText = "HIZLI TARAMA ÇALIŞIYOR";
                        ProtectionStatusColor = "#2196F3";
                    });
                };

                _scanCoordinator.ScanCompleted += (result) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        IsScanning = false;
                        ScanProgress = 100;
                        LastScanTime = "Az önce";
                        IncrementDailyScanned(result.ScannedFiles);
                        ProtectionStatusText = result.Findings.Count > 0 ? "TEHDİT BULUNDU" : "GÜVENDESİNİZ";
                        ProtectionBadgeText = result.Findings.Count > 0 ? $"{result.Findings.Count} ŞÜPHELİ BULGU" : "GERÇEK ZAMANLI KORUMA AKTİF";
                        ProtectionStatusColor = result.Findings.Count > 0 ? "#C41E1E" : "#4CAF50";
                        QuickScanButtonText = "TEKRAR TARA";
                        PendingFindingsCount = result.Findings.Count;

                        _ = RefreshMonthlyQuarantineCountAsync();

                        if (result.Findings.Count > 0)
                        {
                            TriggerToast($"Hızlı tarama tamamlandı: {result.Findings.Count} riskli öğe tespit edildi!", "Warning");
                        }
                        else
                        {
                            TriggerToast($"Hızlı tarama tamamlandı! {result.ScannedFiles:N0} dosya incelendi, tehdit bulunamadı.", "Success");
                        }
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
                    QuickScanButtonText = "DURDUR";
                    ProtectionStatusText = "SİSTEM TARANIYOR...";
                    ProtectionBadgeText = "HIZLI TARAMA ÇALIŞIYOR";
                    ProtectionStatusColor = "#2196F3";
                }
            }

            if (_ipcClient != null)
            {
                _ipcClient.StatusChanged += (s) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        IsServiceConnected = true;
                        ThreatsBocked24h = s.TotalThreatsBlocked24h;
                    });
                };
            }

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
            if (value)
            {
                _ransomwareEngine?.StartShield();
                UpdateRansomwareStateTexts(true);
                TriggerToast("Fidye Kalkanı Devrede! Canary yem tuzakları ve dosya şifreleme izleme motoru aktif.", "Success");
            }
            else
            {
                _ransomwareEngine?.StopShield();
                UpdateRansomwareStateTexts(false);
                TriggerToast("Fidye Kalkanı Devre Dışı Bırakıldı.", "Warning");
            }

            if (_settingsService != null)
            {
                _settingsService.Current.IsRansomwareShieldEnabled = value;
                _ = _settingsService.SaveAsync();
            }
        }

        private void UpdateRansomwareStateTexts(bool active)
        {
            if (active)
            {
                RansomwareStatusText = "Açık";
                RansomwareActionText = "Korumalı";
                RansomwareStatusColor = "#4CAF50";
                RansomwareTitle = "Fidye Kalkanı Devrede (Tam Koruma)";
                RansomwareDescription = "Belgelerinizi ve resimlerinizi şifreleme girişimlerine karşı korur.";
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
    }
}
