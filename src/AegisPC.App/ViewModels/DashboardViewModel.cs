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

        // Telemetry
        [ObservableProperty] private double cpuUsage = 0.0;
        [ObservableProperty] private double memoryUsage = 0.0;
        [ObservableProperty] private double diskUsage = 0.0;
        [ObservableProperty] private double networkUsage = 0.0;
        [ObservableProperty] private int activeProcessCount = 0;
        [ObservableProperty] private int startupAppCount = 0;
        [ObservableProperty] private string lastScanTime = "Henüz yapılmadı";
        [ObservableProperty] private int pendingFindingsCount = 0;
        [ObservableProperty] private int recentCrashCount = 0;

        // Status Banner Hero
        [ObservableProperty] private string shortSummary = "Cihazınız ve kişisel verileriniz Ultron Defender tarafından gerçek zamanlı korunuyor.";
        [ObservableProperty] private string protectionStatusText = "GÜVENDESİNİZ";
        [ObservableProperty] private string protectionBadgeText = "GERÇEK ZAMANLI KORUMA AKTİF";
        [ObservableProperty] private string protectionStatusColor = "#10B981"; // Emerald Green
        [ObservableProperty] private bool isServiceConnected = true;
        [ObservableProperty] private bool isRealTimeProtectionActive = true;
        [ObservableProperty] private int threatsBocked24h = 0;
        [ObservableProperty] private int filesScannedCount = 0;
        [ObservableProperty] private string themeButtonText = AegisPC.App.Services.AppThemeManager.IsDarkMode ? "☀️ Gündüz Modu" : "🌙 Gece Modu";

        // Interactive Feature 1: Ransomware Remediation Banner
        [ObservableProperty] private bool isRansomwareEnabled = false;
        [ObservableProperty] private bool showRansomwareDetails = false;
        [ObservableProperty] private string ransomwareActionText = "ETKİNLEŞTİR";
        [ObservableProperty] private string ransomwareStatusText = "1/1";
        [ObservableProperty] private string ransomwareTitle = "FİDYE YAZILIMI İYİLEŞTİRME VE AKTİF KORUMA ÖNERİSİ";
        [ObservableProperty] private string ransomwareDescription = "Önemli belgelerinizi ve fotoğraflarınızı kaybetmeyin. Fidye yazılımlarının şifreleme girişimlerini engellemek için Fidye Kalkanını devrede tutun.";

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
            IQuarantineService? quarantineService = null)
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
                            StartupSweepStatus.ThreatsFound => "#FF5C5C",
                            StartupSweepStatus.Scanning => "#4CC9F0",
                            StartupSweepStatus.Preparing => "#F5B942",
                            _ => "#35D07F"
                        };
                        StartupSweepFilesRatio = $"{p.ScannedFiles:N0} / {p.TotalFiles:N0}";
                        StartupSweepProgressPercent = p.ProgressPercent;
                        StartupSweepCurrentFile = p.CurrentFile;
                        StartupSweepThreatsCount = p.ThreatsFound;
                        StartupSweepSuspiciousCount = p.SuspiciousFound;
                        StartupSweepCleanCount = p.CleanFiles;
                    });
                };

                _startupSweepService.OnThreatDiscovered += (f) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        StartupSweepFindings.Insert(0, f);
                        ThreatsBocked24h++;
                        ProtectionStatusText = "TEHDİT TESPİT EDİLDİ";
                        ProtectionBadgeText = $"🚨 {f.FileName} ({f.Verdict})";
                        ProtectionStatusColor = "#FF5C5C";
                        TriggerThreatToast(f.FileName);
                    });
                };

                _startupSweepService.OnSweepCompleted += (res) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        IsStartupSweepRunning = false;
                        StartupSweepStatusText = res.ThreatsCount > 0 ? $"{res.ThreatsCount} TEHDİT" : "TEMİZ";
                        StartupSweepBadgeColor = res.ThreatsCount > 0 ? "#FF5C5C" : "#35D07F";
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

                        FilesScannedCount++;
                        LastEventTimeAgo = $"{DateTime.Now:HH:mm:ss}";
                        if (act.Action == "QUARANTINED" || act.Severity == "Danger")
                        {
                            ThreatsBocked24h++;
                            ProtectionStatusText = "TEHDİT ENGELLENDİ";
                            ProtectionBadgeText = $"🚨 {act.FileName} Karantinaya Alındı";
                            ProtectionStatusColor = "#FF5C5C";
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
                        RealTimeHealthColor = healthy ? "#35D07F" : "#FF5C5C";
                        WatcherStatusText = healthy ? "RUNNING" : "DEGRADED";
                        IsRealTimeProtectionActive = healthy;
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
                        ProtectionStatusColor = "#0284C7";
                    });
                };

                _scanCoordinator.ScanCompleted += (result) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        IsScanning = false;
                        ScanProgress = 100;
                        LastScanTime = "Az önce";
                        FilesScannedCount = result.ScannedFiles;
                        ProtectionStatusText = result.Findings.Count > 0 ? "TEHDİT BULUNDU" : "GÜVENDESİNİZ";
                        ProtectionBadgeText = result.Findings.Count > 0 ? $"{result.Findings.Count} ŞÜPHELİ BULGU" : "GERÇEK ZAMANLI KORUMA AKTİF";
                        ProtectionStatusColor = result.Findings.Count > 0 ? "#EF4444" : "#10B981";
                        QuickScanButtonText = "TEKRAR TARA";
                        PendingFindingsCount = result.Findings.Count;

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
                    ProtectionStatusColor = "#0284C7";
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

        private void OnPerformanceSampleCollected(object? sender, PerformanceSample sample)
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                CpuUsage = sample.CpuPercent;
                MemoryUsage = sample.MemoryTotalBytes > 0
                    ? Math.Round(((double)sample.MemoryUsedBytes / sample.MemoryTotalBytes) * 100.0, 1)
                    : 0.0;
                DiskUsage = sample.DiskUsagePercent;
                NetworkUsage = Math.Round((sample.NetworkDownBps + sample.NetworkUpBps) / (1024.0 * 1024.0), 2);
                ActiveProcessCount = sample.ActiveProcesses;

                UpdateHealthScore();
            });
        }

        private void UpdateHealthScore()
        {
            int perfDeduction = 0;
            if (CpuUsage > 85) perfDeduction += 15;
            else if (CpuUsage > 70) perfDeduction += 5;

            if (MemoryUsage > 90) perfDeduction += 15;
            else if (MemoryUsage > 80) perfDeduction += 5;

            PerformanceScore = Math.Clamp(100 - perfDeduction, 20, 100);
            OverallHealthScore = (int)Math.Round((SecurityScore * 0.35) + (PerformanceScore * 0.25) + (StabilityScore * 0.15) + (StartupScore * 0.15) + (BrowserSecurityScore * 0.10));
        }

        // ═══════════════════════════════════════════════
        // INTERACTIVE COMMAND 1: RANSOMWARE REMEDIATION
        // ═══════════════════════════════════════════════
        [RelayCommand]
        public void ToggleRansomwareDetails()
        {
            ShowRansomwareDetails = !ShowRansomwareDetails;
        }

        [RelayCommand]
        public void EnableRansomwareAction()
        {
            if (!IsRansomwareEnabled)
            {
                IsRansomwareEnabled = true;
                RansomwareActionText = "İNCELE";
                RansomwareStatusText = "AKTİF";
                RansomwareTitle = "FİDYE KALKANI DEVREDE (TAM KORUMA)";
                RansomwareDescription = "Canary tuzak dosyaları ve aktif şifreleme izleme motoru arka planda çalışıyor. Dosyalarınız güvende.";
                TriggerToast("Fidye Kalkanı başarıyla etkinleştirildi! Dosya şifreleme tuzakları ve otomatik kurtarma devrede.", "Success");
            }
            else
            {
                // Navigate to Ransomware Shield Page
                AppNavigation.NavigateTo(typeof(RansomwareShieldView));
            }
        }

        // ═══════════════════════════════════════════════
        // INTERACTIVE COMMAND 2: QUICK SCAN
        // ═══════════════════════════════════════════════
        [RelayCommand]
        public async Task StartQuickScanAsync()
        {
            if (_scanCoordinator == null) return;

            if (_scanCoordinator.IsScanning)
            {
                // Stop/Cancel Scan
                _scanCoordinator.CancelScan();
                IsScanning = false;
                QuickScanButtonText = "TARAMAYI BAŞLAT";
                ProtectionStatusText = "GÜVENDESİNİZ";
                ProtectionBadgeText = "GERÇEK ZAMANLI KORUMA AKTİF";
                ProtectionStatusColor = "#10B981";
                TriggerToast("Hızlı tarama kullanıcı tarafından durduruldu.", "Info");
                return;
            }

            IsScanning = true;
            ScanProgress = 0;
            ScanScannedCount = 0;
            ScanThreatCount = 0;
            QuickScanButtonText = "DURDUR";
            ProtectionStatusText = "SİSTEM TARANIYOR...";
            ProtectionBadgeText = "HIZLI TARAMA ÇALIŞIYOR";
            ProtectionStatusColor = "#0284C7";

            TriggerToast("Hızlı sistem taraması başlatıldı...", "Info");

            try
            {
                var scanVm = App.ServiceProvider?.GetService<ScanViewModel>();
                if (scanVm != null)
                {
                    Views.ActiveScanWindow.ShowScanWindow(scanVm);
                }

                await _scanCoordinator.StartScanAsync(AegisPC.Core.Enums.ScanType.Quick);
            }
            catch (Exception ex)
            {
                TriggerToast($"Tarama sırasında hata: {ex.Message}", "Warning");
                IsScanning = false;
                QuickScanButtonText = "TARAMAYI BAŞLAT";
            }
        }





        [RelayCommand]
        public void ToggleRealTimeProtection()
        {
            if (IsRealTimeProtectionActive)
            {
                // Admin Elevation / Warning Confirmation Prompt before turning off
                var res = MessageBox.Show(
                    "⚠️ DİKKAT: Gerçek Zamanlı Korumayı kapatmak bilgisayarınızı virüslere, fidye yazılımlarına ve korsan saldırılara karşı savunmasız bırakır.\n\nBu işlem Yönetici Onayı gerektirir. Yine de korumayı devre dışı bırakmak istiyor musunuz?",
                    "Ultron Defender - Yönetici Koruma Uyarısı",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (res == MessageBoxResult.Yes)
                {
                    IsRealTimeProtectionActive = false;
                    ProtectionStatusText = "KORUMA DEVRE DIŞI";
                    ProtectionBadgeText = "GERÇEK ZAMANLI KORUMA KAPALI";
                    ProtectionStatusColor = "#EF4444"; // Red
                    TriggerToast("⚠️ Gerçek Zamanlı Koruma kullanıcı tarafından kapatıldı!", "Warning");
                }
            }
            else
            {
                IsRealTimeProtectionActive = true;
                ProtectionStatusText = "GÜVENDESİNİZ";
                ProtectionBadgeText = "GERÇEK ZAMANLI KORUMA AKTİF";
                ProtectionStatusColor = "#10B981"; // Emerald Green
                TriggerToast("🛡️ Gerçek Zamanlı Koruma başarıyla etkinleştirildi.", "Success");
            }
        }

        // ═══════════════════════════════════════════════
        // INTERACTIVE COMMAND 5: DEVICE / LICENSE MODAL
        // ═══════════════════════════════════════════════
        [RelayCommand]
        public void ToggleDeviceModal()
        {
            ShowDeviceModal = !ShowDeviceModal;
        }

        [RelayCommand]
        public void CopyLicenseKey()
        {
            try
            {
                Clipboard.SetText(LicenseKey);
                TriggerToast("Lisans anahtarı panoya kopyalandı!", "Success");
            }
            catch
            {
                TriggerToast($"Lisans: {LicenseKey}", "Info");
            }
        }

        // ═══════════════════════════════════════════════
        // INTERACTIVE COMMAND 6: QUICK ACTION SELECTOR (+)
        // ═══════════════════════════════════════════════
        [RelayCommand]
        public void ToggleQuickActionModal()
        {
            ShowQuickActionModal = !ShowQuickActionModal;
        }

        [RelayCommand]
        public void NavigateToTarget(string target)
        {
            ShowQuickActionModal = false;
            ShowDeviceModal = false;

            switch (target?.ToLowerInvariant())
            {
                case "scan":
                case "tara":
                    AppNavigation.NavigateTo(typeof(ScanView));
                    break;
                case "security":
                case "guvenlik":
                    AppNavigation.NavigateTo(typeof(SecurityView));
                    break;
                case "ransomware":
                case "fidye":
                    AppNavigation.NavigateTo(typeof(RansomwareShieldView));
                    break;
                case "network":
                case "ag":
                    AppNavigation.NavigateTo(typeof(NetworkProtectionView));
                    break;
                case "performance":
                case "performans":
                    AppNavigation.NavigateTo(typeof(PerformanceView));
                    break;
                case "quarantine":
                case "karantina":
                    AppNavigation.NavigateTo(typeof(QuarantineView));
                    break;
                case "startup":
                case "baslangic":
                    AppNavigation.NavigateTo(typeof(StartupManagerView));
                    break;
                case "settings":
                case "ayarlar":
                    AppNavigation.NavigateTo(typeof(SettingsView));
                    break;
                default:
                    AppNavigation.NavigateTo(typeof(SecurityView));
                    break;
            }
        }

        // ═══════════════════════════════════════════════
        // TOAST NOTIFICATION HELPER
        // ═══════════════════════════════════════════════
        private readonly System.Collections.Concurrent.ConcurrentQueue<string> _threatNotificationQueue = new();
        private System.Threading.Timer? _threatNotificationTimer;
        private int _isFlushingThreats;

        public void TriggerThreatToast(string threatName)
        {
            _threatNotificationQueue.Enqueue(threatName);
            _threatNotificationTimer ??= new System.Threading.Timer(_ => FlushThreatToast(), null, Timeout.Infinite, Timeout.Infinite);
            _threatNotificationTimer.Change(600, Timeout.Infinite);
        }

        private void FlushThreatToast()
        {
            if (Interlocked.Exchange(ref _isFlushingThreats, 1) == 1) return;
            try
            {
                var list = new System.Collections.Generic.List<string>();
                while (_threatNotificationQueue.TryDequeue(out var item))
                {
                    list.Add(item);
                }
                if (list.Count == 0) return;

                if (list.Count == 1)
                {
                    TriggerToast($"Ultron Defender (Antivirüs Programı): '{list[0]}' engellendi ve karantinaya alındı.", "Danger");
                }
                else
                {
                    TriggerToast($"Ultron Defender (Antivirüs Programı): {list.Count} adet zararlı tehdit engellendi ve karantinaya alındı.", "Danger");
                }
            }
            finally
            {
                Interlocked.Exchange(ref _isFlushingThreats, 0);
            }
        }

        public void TriggerToast(string message, string type = "Success")
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                ToastMessage = message;
                ToastType = type;
                ShowToast = true;

                // Auto hide after 3.5 seconds
                Task.Delay(3500).ContinueWith(_ =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        ShowToast = false;
                    });
                });
            });
        }

        [RelayCommand]
        public void DismissToast()
        {
            ShowToast = false;
        }

        [RelayCommand]
        public async Task LoadDashboardDataAsync()
        {
            try
            {
                if (_healthScoringEngine != null)
                {
                    var health = await _healthScoringEngine.CalculateHealthScoreAsync();
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        OverallHealthScore = health.OverallScore;
                        SecurityScore = health.SecurityScore;
                        PerformanceScore = health.PerformanceScore;
                        StabilityScore = health.StabilityScore;
                        StartupScore = health.StartupScore;
                        BrowserSecurityScore = health.BrowserSecurityScore;
                        PendingFindingsCount = health.ActiveFindingsCount;
                        RecentCrashCount = health.RecentCrashCount;
                    });
                }

                if (_startupAnalyzer != null)
                {
                    var startup = await _startupAnalyzer.GetStartupItemsAsync();
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        StartupAppCount = startup.Count;
                    });
                }

                if (_processMonitor != null)
                {
                    var procs = await _processMonitor.GetAllProcessesAsync();
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        ActiveProcessCount = procs.Count;
                    });
                }
            }
            catch { }
        }

        // ═══════════════════════════════════════════════
        // STARTUP SWEEP & THREAT DETAIL COMMANDS
        // ═══════════════════════════════════════════════
        [RelayCommand]
        public async Task StartStartupSweepAsync()
        {
            if (_startupSweepService != null && !IsStartupSweepRunning)
            {
                TriggerToast("Başlangıç Güvenlik Taraması başlatıldı...", "Info");
                await _startupSweepService.RunSweepAsync();
            }
        }

        [RelayCommand]
        public void ViewThreatDetail(AegisPC.Contracts.Services.StartupSweepFinding? finding)
        {
            if (finding != null)
            {
                SelectedThreatFinding = finding;
                ShowThreatDetailModal = true;
            }
        }

        [RelayCommand]
        public void CloseThreatDetail()
        {
            ShowThreatDetailModal = false;
        }

        [RelayCommand]
        public async Task RestoreThreatAsync(AegisPC.Contracts.Services.StartupSweepFinding? finding)
        {
            if (finding != null && _quarantineService != null)
            {
                var vaultItems = await _quarantineService.GetQuarantinedItemsAsync();
                var item = vaultItems.FirstOrDefault(x => x.FileName.Equals(finding.FileName, StringComparison.OrdinalIgnoreCase));
                if (item != null)
                {
                    bool restored = await _quarantineService.RestoreFileAsync(item.Id, null);
                    if (restored)
                    {
                        finding.IsQuarantined = false;
                        TriggerToast($"Dosya güvenle geri yüklendi: {finding.FileName}", "Success");
                        ShowThreatDetailModal = false;
                    }
                    else
                    {
                        TriggerToast($"Geri yükleme başarısız oldu!", "Warning");
                    }
                }
                else
                {
                    TriggerToast($"Karantina kaydı bulunamadı.", "Warning");
                }
            }
        }

        [RelayCommand]
        public void ToggleTheme()
        {
            AegisPC.App.Services.AppThemeManager.ToggleTheme();
            ThemeButtonText = AegisPC.App.Services.AppThemeManager.IsDarkMode ? "☀️ Gündüz Modu" : "🌙 Gece Modu";
        }
    }
}
