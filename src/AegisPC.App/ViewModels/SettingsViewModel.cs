using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Infrastructure.Configuration;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wpf.Ui.Appearance;
using AegisPC.App.Services;
using AegisPC.Security.RealTime;

namespace AegisPC.App.ViewModels
{
    public partial class SettingsViewModel : ObservableObject
    {
        private readonly SettingsService? _settingsService;
        private readonly IBackgroundProtectionService? _backgroundProtectionService;
        private readonly IRansomwareProtectionEngine? _ransomwareProtectionEngine;
        private readonly IAuditLogService? _auditLogService;
        private readonly IWindowsToastNotificationService? _toastNotificationService;
        private readonly IReputationService? _reputationService;

        [ObservableProperty]
        private string pageTitle = "Uygulama ve Güvenlik Ayarları";

        [ObservableProperty]
        private bool isDarkMode = false;

        [ObservableProperty]
        private ThemeMode selectedThemeMode = ThemeMode.Light;

        [ObservableProperty]
        private bool isLightThemeSelected = true;

        [ObservableProperty]
        private bool isDarkThemeSelected = false;

        [ObservableProperty]
        private bool isSystemThemeSelected = false;

        [ObservableProperty]
        private bool isRealTimeMonitoringEnabled = true;

        [ObservableProperty]
        private bool notificationsEnabled = true;

        [ObservableProperty]
        private bool scanScheduleEnabled = false;

        [ObservableProperty]
        private int sampleIntervalSeconds = 2;

        [ObservableProperty]
        private bool isFileProtectionEnabled = true;

        [ObservableProperty]
        private bool isProcessMonitoringEnabled = true;

        [ObservableProperty]
        private bool isRansomwareShieldEnabled = true;

        [ObservableProperty]
        private bool isGameCrackWatchdogEnabled = true;

        [ObservableProperty]
        private bool isNetworkProtectionEnabled = AegisPC.Core.Configuration.FeatureFlags.IsNetworkShieldActive;

        [ObservableProperty]
        private bool isCloudLookupEnabled = false;

        [ObservableProperty]
        private bool isSampleSubmissionEnabled = false;

        [ObservableProperty]
        private bool isAutoUpdateEnabled = true;

        [ObservableProperty]
        private string lastUpdateCheck = "Son kontrol: Bugün (Güncel)";

        [ObservableProperty]
        private int scheduledScanHour = 12;

        [ObservableProperty]
        private string scheduledScanDay = "Her Gün (Günde 1 Kez - Önerilen)";

        [ObservableProperty]
        private ObservableCollection<string> scanPeriods = new()
        {
            "Her Gün (Günde 1 Kez - Önerilen)",
            "12 Saatte Bir",
            "6 Saatte Bir",
            "3 Saatte Bir",
            "1 Saatte Bir",
            "30 Dakikada Bir (Yüksek Güvenlik)"
        };

        [ObservableProperty]
        private string selectedScanPeriod = "Her Gün (Günde 1 Kez - Önerilen)";

        [ObservableProperty]
        private bool isFrequentScanWarningVisible = false;

        [ObservableProperty]
        private ObservableCollection<string> scanHours = new();

        [ObservableProperty]
        private string selectedScanHourString = "12:00";

        partial void OnSelectedScanPeriodChanged(string value)
        {
            ScheduledScanDay = value;
            IsFrequentScanWarningVisible = value != null && value.Contains("30 Dakika");
        }

        partial void OnSelectedScanHourStringChanged(string value)
        {
            if (!string.IsNullOrEmpty(value) && int.TryParse(value.Split(':')[0].Trim(), out var h))
            {
                ScheduledScanHour = h;
            }
        }

        [ObservableProperty]
        private string statusMessage = string.Empty;

        [ObservableProperty]
        private bool isProtectionWarningVisible = false;

        [ObservableProperty]
        private string protectionWarningText = string.Empty;

        [ObservableProperty]
        private ScanResourceMode selectedResourceMode = ScanResourceMode.Auto;

        [ObservableProperty]
        private ObservableCollection<ResourceModeItem> resourceModes = new()
        {
            new ResourceModeItem { Mode = ScanResourceMode.Auto, Title = "Otomatik (Adaptif Akıllı Yönetim)", Description = "Sistem donanımına, batarya durumuna ve disk türüne (SSD/HDD) göre hızı anlık uyarlar." },
            new ResourceModeItem { Mode = ScanResourceMode.VeryLow, Title = "Çok Düşük (Sıfır Kasma - 1 Çekirdek)", Description = "En fazla 1 çekirdek ve 128 MB RAM kullanır. Günlük işlerde hiçbir yavaşlama hissettirmez." },
            new ResourceModeItem { Mode = ScanResourceMode.Low, Title = "Düşük (Oyun ve Çalışma Modu)", Description = "2 çekirdek sınırı ve 256 MB RAM kotası ile sessiz ve hafif arka plan taraması yapar." },
            new ResourceModeItem { Mode = ScanResourceMode.Balanced, Title = "Dengeli (Standart Kullanım)", Description = "İşlemci çekirdeklerinin yarısını kullanır; hız ve kaynak tasarrufunu dengeler." },
            new ResourceModeItem { Mode = ScanResourceMode.High, Title = "Yüksek (Hızlı Güvenlik Taraması)", Description = "İşlemci gücünün %75'ini kullanarak taramayı kısa sürede tamamlar." },
            new ResourceModeItem { Mode = ScanResourceMode.Maximum, Title = "Maksimum (Tam Güç - Tüm Çekirdekler)", Description = "Tüm CPU çekirdeklerini ve yüksek RAM kotasını kullanarak en yüksek hızda çalışır." }
        };

        [ObservableProperty]
        private ResourceModeItem? selectedResourceModeItem;

        [ObservableProperty]
        private bool isResourceThrottlingWarningVisible = false;

        partial void OnSelectedResourceModeItemChanged(ResourceModeItem? value)
        {
            if (value != null)
            {
                SelectedResourceMode = value.Mode;
                IsResourceThrottlingWarningVisible = value.Mode == ScanResourceMode.VeryLow || value.Mode == ScanResourceMode.Low;
                _ = SaveSettingsAsync();
                _ = LogAuditAsync("Tarama Kaynak Modu", value.Title);
            }
        }

        public SettingsViewModel(
            SettingsService? settingsService = null,
            IBackgroundProtectionService? backgroundProtectionService = null,
            IRansomwareProtectionEngine? ransomwareProtectionEngine = null,
            IAuditLogService? auditLogService = null,
            IWindowsToastNotificationService? toastNotificationService = null,
            IReputationService? reputationService = null)
        {
            _settingsService = settingsService;
            _backgroundProtectionService = backgroundProtectionService;
            _ransomwareProtectionEngine = ransomwareProtectionEngine;
            _auditLogService = auditLogService;
            _toastNotificationService = toastNotificationService;
            _reputationService = reputationService;
            AppThemeManager.ThemeChanged += OnAppThemeChanged;
            LoadSettings();
        }

        private void OnAppThemeChanged(ThemeMode mode)
        {
            if (SelectedThemeMode != mode)
            {
                SelectedThemeMode = mode;
                IsLightThemeSelected = mode == ThemeMode.Light;
                IsDarkThemeSelected = mode == ThemeMode.Dark;
                IsSystemThemeSelected = mode == ThemeMode.System;
                IsDarkMode = AppThemeManager.IsDarkMode;
            }
        }

        public void SelectTheme(ThemeMode mode)
        {
            SelectedThemeMode = mode;
            IsLightThemeSelected = mode == ThemeMode.Light;
            IsDarkThemeSelected = mode == ThemeMode.Dark;
            IsSystemThemeSelected = mode == ThemeMode.System;
            IsDarkMode = AppThemeManager.IsDarkMode;

            AppThemeManager.ApplyTheme(mode);
            if (_settingsService != null)
            {
                _settingsService.Current.Theme = mode;
                _ = _settingsService.SaveAsync();
            }

            StatusMessage = mode switch
            {
                ThemeMode.Light => "Açık tema uygulandı.",
                ThemeMode.Dark => "Koyu tema uygulandı.",
                ThemeMode.System => "Sistem teması takip ediliyor.",
                _ => "Tema güncellendi."
            };
        }

        [RelayCommand]
        public void SetLightTheme() => SelectTheme(ThemeMode.Light);

        [RelayCommand]
        public void SetDarkTheme() => SelectTheme(ThemeMode.Dark);

        [RelayCommand]
        public void SetSystemTheme() => SelectTheme(ThemeMode.System);

        private void LoadSettings()
        {
            var currentTheme = _settingsService?.Current?.Theme ?? AppThemeManager.CurrentTheme;
            SelectedThemeMode = currentTheme;
            IsLightThemeSelected = currentTheme == ThemeMode.Light;
            IsDarkThemeSelected = currentTheme == ThemeMode.Dark;
            IsSystemThemeSelected = currentTheme == ThemeMode.System;
            IsDarkMode = AppThemeManager.IsDarkMode;

            if (_settingsService != null)
            {
                var s = _settingsService.Current;
                IsRealTimeMonitoringEnabled = s.IsRealTimeMonitoringEnabled;
                NotificationsEnabled = s.NotificationsEnabled;
                ScanScheduleEnabled = s.ScanScheduleEnabled;
                SampleIntervalSeconds = Math.Max(1, s.PerformanceSampleIntervalMs / 1000);
                IsFileProtectionEnabled = s.IsFileProtectionEnabled;
                IsRansomwareShieldEnabled = s.IsRansomwareShieldEnabled;
                IsProcessMonitoringEnabled = s.IsProcessMonitoringEnabled;
                IsCloudLookupEnabled = s.IsCloudReputationEnabled;
                ScheduledScanHour = s.ScheduledScanHour;
                ScheduledScanDay = s.ScheduledScanDay;
                SelectedResourceMode = s.ScanResourceMode;
                SelectedResourceModeItem = ResourceModes.FirstOrDefault(m => m.Mode == s.ScanResourceMode) ?? ResourceModes[0];
                IsResourceThrottlingWarningVisible = SelectedResourceMode == ScanResourceMode.VeryLow || SelectedResourceMode == ScanResourceMode.Low;
            }
            else
            {
                IsCloudLookupEnabled = _reputationService?.IsCloudLookupEnabled ?? AegisPC.Core.Configuration.FeatureFlags.IsCloudLookupActive;
                SelectedResourceModeItem = ResourceModes[0];
            }

            ScanHours.Clear();
            for (int i = 0; i < 24; i++)
            {
                var suffix = i switch
                {
                    0 => " (Gece Yarısı)",
                    8 => " (Sabah)",
                    12 => " (Öğlen)",
                    18 => " (Akşam)",
                    22 => " (Gece)",
                    _ => ""
                };
                ScanHours.Add($"{i:D2}:00{suffix}");
            }

            SelectedScanHourString = ScanHours.FirstOrDefault(h => h.StartsWith($"{ScheduledScanHour:D2}:00")) ?? $"{ScheduledScanHour:D2}:00";
            SelectedScanPeriod = ScanPeriods.FirstOrDefault(p => p.Equals(ScheduledScanDay, StringComparison.OrdinalIgnoreCase)) 
                ?? ScanPeriods.FirstOrDefault(p => p.Contains(ScheduledScanDay, StringComparison.OrdinalIgnoreCase)) 
                ?? ScanPeriods[0];

            EvaluateProtectionWarning();
        }

        private void EvaluateProtectionWarning()
        {
            if (!IsFileProtectionEnabled || !IsRansomwareShieldEnabled)
            {
                IsProtectionWarningVisible = true;
                ProtectionWarningText = "⚠️ DİKKAT: Temel güvenlik korumalarından biri veya birkaçı devre dışı bırakıldı! Cihazınız saldırılara karşı savunmasız kalabilir.";
            }
            else
            {
                IsProtectionWarningVisible = false;
                ProtectionWarningText = string.Empty;
            }
        }

        partial void OnIsFileProtectionEnabledChanged(bool value)
        {
            if (value)
            {
                _backgroundProtectionService?.StartProtection();
            }
            else
            {
                _backgroundProtectionService?.StopProtection();
            }
            EvaluateProtectionWarning();
            _ = SaveSettingsAsync();
            _ = LogAuditAsync("Dosya Kalkanı", value ? "Aktif Edildi" : "Devre Dışı Bırakıldı (UYARI)");
        }

        partial void OnIsRansomwareShieldEnabledChanged(bool value)
        {
            if (value)
            {
                _ransomwareProtectionEngine?.StartShield();
            }
            else
            {
                _ransomwareProtectionEngine?.StopShield();
            }
            EvaluateProtectionWarning();
            _ = SaveSettingsAsync();
            _ = LogAuditAsync("Fidye Kalkanı", value ? "Aktif Edildi" : "Devre Dışı Bırakıldı (UYARI)");
        }

        partial void OnIsProcessMonitoringEnabledChanged(bool value)
        {
            _ = SaveSettingsAsync();
            _ = LogAuditAsync("Süreç İzleme", value ? "Aktif Edildi" : "Devre Dışı Bırakıldı");
        }

        partial void OnIsGameCrackWatchdogEnabledChanged(bool value)
        {
            AegisPC.Core.Configuration.FeatureFlags.IsGamerCrackShieldActive = value;
            _ = SaveSettingsAsync();
            _ = LogAuditAsync("Oyun ve Crack Kalkanı", value ? "Aktif Edildi" : "Devre Dışı Bırakıldı");
        }

        partial void OnIsCloudLookupEnabledChanged(bool value)
        {
            AegisPC.Core.Configuration.FeatureFlags.IsCloudLookupActive = value;
            if (_reputationService != null)
            {
                _reputationService.IsCloudLookupEnabled = value;
            }
            if (_settingsService != null)
            {
                _settingsService.Current.IsCloudReputationEnabled = value;
            }
            _ = SaveSettingsAsync();
            _ = LogAuditAsync("Bulut Tehdit Sorgulama", value ? "Aktif Edildi" : "Devre Dışı Bırakıldı");
        }

        partial void OnNotificationsEnabledChanged(bool value)
        {
            if (_settingsService != null)
            {
                _settingsService.Current.NotificationsEnabled = value;
            }
            _ = SaveSettingsAsync();
            _ = LogAuditAsync("Bildirimler", value ? "Aktif Edildi" : "Devre Dışı Bırakıldı (Sessiz Mod)");
            StatusMessage = value ? "Kritik tehdit bildirimleri etkinleştirildi." : "Bildirimler kapatıldı (Sessiz mod devrede).";
        }

        partial void OnIsRealTimeMonitoringEnabledChanged(bool value)
        {
            if (_settingsService != null)
            {
                _settingsService.Current.IsRealTimeMonitoringEnabled = value;
            }
            _ = SaveSettingsAsync();
            _ = LogAuditAsync("Donanım İzleme", value ? "Aktif Edildi" : "Devre Dışı Bırakıldı");
        }

        partial void OnIsNetworkProtectionEnabledChanged(bool value)
        {
            AegisPC.Core.Configuration.FeatureFlags.IsNetworkShieldActive = value;
            StatusMessage = value ? "Ağ, DNS ve Web Kalkanı devrede." : "Ağ, DNS ve Web Kalkanı durduruldu.";
            _ = SaveSettingsAsync();
            _ = LogAuditAsync("Ağ ve Web Kalkanı", value ? "Aktif Edildi" : "Devre Dışı Bırakıldı");
        }

        private async Task LogAuditAsync(string component, string action)
        {
            if (_auditLogService != null)
            {
                try
                {
                    await _auditLogService.LogActionAsync(
                        action: AuditAction.SettingsChanged,
                        targetType: "SecuritySetting",
                        targetName: component,
                        targetPath: null,
                        details: $"Ayar '{component}' durumu değiştirildi: {action}",
                        result: AuditResult.Success);
                }
                catch { }
            }
        }

        [RelayCommand]
        public async Task SaveSettingsAsync()
        {
            if (_settingsService == null) return;

            var s = _settingsService.Current;
            s.Theme = SelectedThemeMode;
            s.IsRealTimeMonitoringEnabled = IsRealTimeMonitoringEnabled;
            s.NotificationsEnabled = NotificationsEnabled;
            s.ScanScheduleEnabled = ScanScheduleEnabled;
            s.PerformanceSampleIntervalMs = SampleIntervalSeconds * 1000;
            s.IsFileProtectionEnabled = IsFileProtectionEnabled;
            s.IsRansomwareShieldEnabled = IsRansomwareShieldEnabled;
            s.IsProcessMonitoringEnabled = IsProcessMonitoringEnabled;
            s.IsCloudReputationEnabled = IsCloudLookupEnabled;
            s.ScheduledScanHour = ScheduledScanHour;
            s.ScheduledScanDay = ScheduledScanDay;
            s.ScanResourceMode = SelectedResourceMode;
            s.ScheduledScanIntervalHours = SelectedScanPeriod switch
            {
                var p when p.Contains("12 Saat") => 12,
                var p when p.Contains("6 Saat") => 6,
                var p when p.Contains("3 Saat") => 3,
                var p when p.Contains("1 Saat") => 1,
                var p when p.Contains("30 Dakika") => 0,
                _ => 24
            };

            await _settingsService.SaveAsync();
            StatusMessage = "Ayarlar başarıyla kaydedildi.";
        }
    }

    public class ResourceModeItem
    {
        public ScanResourceMode Mode { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;

        public override string ToString() => Title;
    }
}
