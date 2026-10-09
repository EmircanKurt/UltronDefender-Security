using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Infrastructure.Configuration;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wpf.Ui.Appearance;
using AegisPC.App.Services;
using AegisPC.Security.RealTime;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.ViewModels
{
    public partial class SettingsViewModel : ObservableObject, IDisposable
    {
        private readonly SettingsService? _settingsService;
        private readonly IAuditLogService? _auditLogService;
        private readonly IWindowsToastNotificationService? _toastNotificationService;
        private readonly IReputationService? _reputationService;
        private readonly AegisPC.Security.Scanning.IFileHashMatcher? _fileHashMatcher;
        private readonly IScanCoordinatorService? _scanCoordinator;
        private readonly IExclusionService? _exclusionService;
        private readonly IServiceIpcClient? _ipcClient;
        private bool _isApplyingServiceStatus;
        private bool _isLoadingSettings = true;

        [ObservableProperty]
        private ObservableCollection<AegisPC.Core.Models.ExclusionEntry> exclusions = new();

        [ObservableProperty]
        private bool hasNoExclusions = true;

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
        private bool enableAutoQuarantine = true;

        [ObservableProperty]
        private string automaticContainmentStatus = "Otomatik müdahale bu pilotta kapalı; tespit ve uyarılar devam eder.";

        [ObservableProperty]
        private int autoQuarantineThreshold = 85;

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
            if (!_isLoadingSettings && !_isApplyingServiceStatus) _ = SaveSettingsAsync();
        }

        partial void OnSelectedScanHourStringChanged(string value)
        {
            if (!string.IsNullOrEmpty(value) && int.TryParse(value.Split(':')[0].Trim(), out var h))
            {
                ScheduledScanHour = h;
                if (!_isLoadingSettings && !_isApplyingServiceStatus) _ = SaveSettingsAsync();
            }
        }

        [ObservableProperty]
        private string statusMessage = string.Empty;

        /// <summary>Whether the current service observation needs a connection notice or protection warning.</summary>
        [ObservableProperty]
        private bool isProtectionWarningVisible = false;

        /// <summary>Plain-language explanation of unavailable service information or an observed protection limitation.</summary>
        [ObservableProperty]
        private string protectionWarningText = string.Empty;

        /// <summary>Short heading that identifies the connection or observed protection condition without activation terminology.</summary>
        [ObservableProperty]
        private string protectionWarningTitle = string.Empty;

        /// <summary>Presentation severity for the observed condition; missing information uses the neutral information style.</summary>
        [ObservableProperty]
        private string protectionWarningSeverity = nameof(ServiceProtectionNoticeSeverity.Information);

        [ObservableProperty]
        private ScanResourceMode selectedResourceMode = ScanResourceMode.Auto;

        /// <summary>Controls idle maintenance independently from scheduled scans.</summary>
        [ObservableProperty]
        private bool idleScanEnabled = true;
        /// <summary>Minutes of inactivity required before idle maintenance.</summary>
        [ObservableProperty]
        private int idleScanThresholdMinutes = 10;
        /// <summary>Hours between completed idle maintenance scans.</summary>
        [ObservableProperty]
        private int idleScanIntervalHours = 24;
        /// <summary>Defers idle maintenance on battery power.</summary>
        [ObservableProperty]
        private bool skipIdleScanOnBattery = true;

        partial void OnIdleScanEnabledChanged(bool value) { if (!_isLoadingSettings && !_isApplyingServiceStatus) _ = SaveSettingsAsync(); }
        partial void OnIdleScanThresholdMinutesChanged(int value) { if (!_isLoadingSettings && !_isApplyingServiceStatus) _ = SaveSettingsAsync(); }
        partial void OnIdleScanIntervalHoursChanged(int value) { if (!_isLoadingSettings && !_isApplyingServiceStatus) _ = SaveSettingsAsync(); }
        partial void OnSkipIdleScanOnBatteryChanged(bool value) { if (!_isLoadingSettings && !_isApplyingServiceStatus) _ = SaveSettingsAsync(); }

        [ObservableProperty]
        private ObservableCollection<ResourceModeItem> resourceModes = new()
        {
            new ResourceModeItem { Mode = ScanResourceMode.Auto, Title = "Otomatik (Adaptif Akıllı Yönetim)", Description = "Sistem donanımına, batarya durumuna ve disk türüne (SSD/HDD) göre hızı anlık uyarlar." },
            new ResourceModeItem { Mode = ScanResourceMode.VeryLow, Title = "Çok Düşük (1 İşçi)", Description = "En fazla 1 işçi ve düşük bellek bütçesi; tarama daha uzun sürebilir." },
            new ResourceModeItem { Mode = ScanResourceMode.Low, Title = "Düşük (Arka Plan)", Description = "Az sayıda işçi ve sınırlı bellek bütçesiyle günlük kullanıma öncelik verir." },
            new ResourceModeItem { Mode = ScanResourceMode.Balanced, Title = "Dengeli (Standart Kullanım)", Description = "Donanım ve disk sınırları içinde hız ve kaynak kullanımını dengeler." },
            new ResourceModeItem { Mode = ScanResourceMode.High, Title = "Yüksek (Hızlı Tarama)", Description = "Daha fazla eşzamanlı işçi kullanır; hız dosya türü ve disk kapasitesine bağlıdır." },
            new ResourceModeItem { Mode = ScanResourceMode.Maximum, Title = "Maksimum (Donanım Sınırları İçinde)", Description = "Donanımın izin verdiği işçi bütçesini kullanır; HDD ve bellek baskısı sınırları korunur." }
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
                if (_isLoadingSettings || _isApplyingServiceStatus) return;
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
            IReputationService? reputationService = null,
            AegisPC.Security.Scanning.IFileHashMatcher? fileHashMatcher = null,
            IScanCoordinatorService? scanCoordinator = null,
            IExclusionService? exclusionService = null,
            IServiceIpcClient? ipcClient = null,
            IProtectionDisableConfirmation? disableConfirmation = null)
        {
            _settingsService = settingsService;
            _auditLogService = auditLogService;
            _toastNotificationService = toastNotificationService;
            _reputationService = reputationService;
            _fileHashMatcher = fileHashMatcher;
            _scanCoordinator = scanCoordinator;
            _exclusionService = exclusionService;
            _ipcClient = ipcClient;
            _disableConfirmation = disableConfirmation ?? new ProtectionDisableConfirmation();

            if (_ipcClient != null)
            {
                _ipcClient.StatusChanged += ApplyServiceStatus;
            }

            if (_fileHashMatcher != null && _scanCoordinator != null)
            {
                _fileHashMatcher.ActiveScanChecker ??= () => _scanCoordinator.IsScanning;
            }

            AppThemeManager.ThemeChanged += OnAppThemeChanged;
            try { LoadSettings(); }
            finally { _isLoadingSettings = false; }
            StartProtectionStatusFreshnessCheck();
            _ = RequestServiceStatusAsync();
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
                IdleScanEnabled = s.IdleScanEnabled;
                IdleScanThresholdMinutes = s.IdleScanThresholdMinutes;
                IdleScanIntervalHours = s.IdleScanIntervalHours;
                SkipIdleScanOnBattery = s.SkipIdleScanOnBattery;
                SampleIntervalSeconds = Math.Max(1, s.PerformanceSampleIntervalMs / 1000);
                IsFileProtectionEnabled = s.IsFileProtectionEnabled;
                IsUltronAiEnabled = s.IsUltronAiEnabled;
                IsRansomwareShieldEnabled = s.IsRansomwareShieldEnabled;
                IsNetworkProtectionEnabled = s.IsNetworkProtectionEnabled;
                EnableAutoQuarantine = s.EnableAutoQuarantine;
                AutoQuarantineThreshold = s.AutoQuarantineThreshold;
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
            // Numeric settings are authoritative; a stale presentation label must not reset a service-saved interval.
            SelectedScanPeriod = (_settingsService?.Current.ScheduledScanIntervalHours ?? 24) switch
            {
                0 => ScanPeriods[5], 1 => ScanPeriods[4], 3 => ScanPeriods[3],
                6 => ScanPeriods[2], 12 => ScanPeriods[1], _ => ScanPeriods[0]
            };

            EvaluateProtectionWarning();
            _ = LoadExclusionsAsync();
        }

        private void EvaluateProtectionWarning()
        {
            var notice = ServiceProtectionStatusPolicy.Describe(_ipcClient, _lastProtectionStatus, DateTime.UtcNow);
            if (!IsProtectionStatusVerified && notice.Title.Length == 0)
                notice = new ServiceProtectionNotice("Koruma bilgisi alınamadı", "Güncel çalışma durumu için Yenile ile tekrar deneyin.");
            IsProtectionWarningVisible = notice.Title.Length != 0;
            ProtectionWarningTitle = notice.Title;
            ProtectionWarningText = notice.Message;
            ProtectionWarningSeverity = notice.Severity.ToString();
        }

        partial void OnIsFileProtectionEnabledChanged(bool value)
        {
            if (_isApplyingServiceStatus || _isLoadingSettings)
            {
                EvaluateProtectionWarning();
                return;
            }

            _ = RequestServiceProtectionChangeAsync(ransomware: false, enabled: value);
        }

        partial void OnIsRansomwareShieldEnabledChanged(bool value)
        {
            if (_isApplyingServiceStatus || _isLoadingSettings)
            {
                EvaluateProtectionWarning();
                return;
            }

            _ = RequestServiceProtectionChangeAsync(ransomware: true, enabled: value);
        }

        partial void OnEnableAutoQuarantineChanged(bool value)
        {
            if (_isApplyingServiceStatus || _isLoadingSettings) return;

            if (_settingsService != null)
            {
                _settingsService.Current.EnableAutoQuarantine = value;
            }
            _ = SaveSettingsAsync();
            _ = LogAuditAsync("Otomatik Karantina", value ? "Aktif Edildi" : "Devre Dışı Bırakıldı");
        }

        partial void OnScanScheduleEnabledChanged(bool value)
        {
            if (_isApplyingServiceStatus || _isLoadingSettings) return;
            if (_settingsService != null)
                _settingsService.Current.ScanScheduleEnabled = value;
            _ = SaveSettingsAsync();
        }

        partial void OnAutoQuarantineThresholdChanged(int value)
        {
            if (_isApplyingServiceStatus || _isLoadingSettings) return;

            if (_settingsService != null)
            {
                _settingsService.Current.AutoQuarantineThreshold = Math.Clamp(value, 0, 100);
            }
            _ = SaveSettingsAsync();
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
            if (_isApplyingServiceStatus || _isLoadingSettings) return;
            _ = RequestNetworkProtectionChangeAsync(value);
        }

        private async Task LogAuditAsync(string component, string action)
        {
            if (_isLoadingSettings) return;
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

        private async Task SendServiceCommandAsync(ServiceCommandType commandType)
        {
            if (_ipcClient?.IsConnected != true) return;

            try
            {
                await _ipcClient.SendCommandAsync(new ServiceCommand
                {
                    CommandType = commandType,
                    Timestamp = DateTime.UtcNow
                });
                StatusMessage = _ipcClient.IsConnected
                    ? "Koruma isteği servise gönderildi; uygulandığı henüz doğrulanmadı."
                    : "Servis bağlantısı kesildi; koruma isteğinin uygulanması doğrulanamadı.";
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Koruma ayarı servise gönderilemedi.");
                StatusMessage = "Koruma ayarı servise uygulanamadı.";
            }
            finally { await RequestServiceStatusAsync(); }
        }

        private async Task SendServiceSettingsAsync()
        {
            if (_ipcClient?.IsConnected != true) return;

            try
            {
                await _ipcClient.SendCommandAsync(new ServiceCommand
                {
                    CommandType = ServiceCommandType.UpdateSettings,
                    Payload = JsonSerializer.Serialize(new
                    {
                        EnableAutoQuarantine,
                        AutoQuarantineThreshold = Math.Clamp(AutoQuarantineThreshold, 0, 100),
                        ScanScheduleEnabled,
                        ScheduledScanHour,
                        ScheduledScanIntervalHours = GetScheduledScanIntervalHours(),
                        IdleScanEnabled,
                        IdleScanThresholdMinutes = Math.Clamp(IdleScanThresholdMinutes, 1, 240),
                        IdleScanIntervalHours = Math.Clamp(IdleScanIntervalHours, 1, 168),
                        SkipIdleScanOnBattery,
                        ScanResourceMode = SelectedResourceMode
                    }),
                    Timestamp = DateTime.UtcNow
                });
                StatusMessage = _ipcClient.IsConnected
                    ? "Yerel ayarlar kaydedildi; servise uygulama isteği gönderildi (henüz doğrulanmadı)."
                    : "Yerel ayarlar kaydedildi, servis bağlantısı kesildi; servise uygulanmadı.";
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Güvenlik ayarları servise gönderilemedi.");
                StatusMessage = "Güvenlik ayarları servise uygulanamadı.";
            }
            finally { await RequestServiceStatusAsync(); }
        }

        private async Task RequestServiceStatusAsync()
        {
            if (_settingsDisposed) return;
            if (_ipcClient?.IsConnected != true)
            {
                IsProtectionStatusVerified = false;
                UpdateUltronAiObservation();
                EvaluateProtectionWarning();
                return;
            }
            try { ApplyServiceStatus(await _ipcClient.GetStatusAsync()); }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Servis durumu yenilenemedi.");
                StatusMessage = "Servis bağlantısı doğrulanamadı.";
                IsProtectionStatusVerified = false;
                UpdateUltronAiObservation();
                EvaluateProtectionWarning();
            }
        }

        private void ApplyServiceStatus(ProtectionStatus status)
        {
            if (_settingsDisposed) return;
            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            if (dispatcher != null && !dispatcher.CheckAccess())
            {
                dispatcher.InvokeAsync(() => ApplyServiceStatus(status));
                return;
            }
            IsProtectionStatusVerified = ServiceProtectionStatusPolicy.IsVerified(_ipcClient, status);
            _lastProtectionStatus = status;
            UpdateUltronAiObservation();
            if (!status.IsServiceRunning)
            {
                EvaluateProtectionWarning();
                return;
            }
            _isApplyingServiceStatus = true;
            try
            {
                if (IsProtectionStatusVerified)
                {
                    _lastObservedFileProtection = IsFileProtectionEnabled = status.IsRealTimeEnabled;
                    _lastObservedRansomwareProtection = IsRansomwareShieldEnabled = status.IsRansomwareShieldEnabled;
                    _lastObservedNetworkProtection = IsNetworkProtectionEnabled = status.IsNetworkProtectionEnabled;
                    AegisPC.Core.Configuration.FeatureFlags.IsNetworkShieldActive = status.IsNetworkProtectionEnabled;
                }
                ScanScheduleEnabled = status.ScanScheduleEnabled;
                IdleScanEnabled = status.IdleScanEnabled;
                IdleScanThresholdMinutes = Math.Clamp(status.IdleScanThresholdMinutes, 1, 240);
                IdleScanIntervalHours = Math.Clamp(status.IdleScanIntervalHours, 1, 168);
                SkipIdleScanOnBattery = status.SkipIdleScanOnBattery;
                ScheduledScanHour = Math.Clamp(status.ScheduledScanHour, 0, 23);
                SelectedScanHourString = ScanHours.FirstOrDefault(h => h.StartsWith($"{ScheduledScanHour:D2}:00")) ?? $"{ScheduledScanHour:D2}:00";
                SelectedScanPeriod = status.ScheduledScanIntervalHours switch
                {
                    0 => ScanPeriods[5], 1 => ScanPeriods[4], 3 => ScanPeriods[3],
                    6 => ScanPeriods[2], 12 => ScanPeriods[1], _ => ScanPeriods[0]
                };
                SelectedResourceModeItem = ResourceModes.FirstOrDefault(m => m.Mode == status.ScanResourceMode) ?? ResourceModes[0];
                EnableAutoQuarantine = status.EnableAutoQuarantine;
                AutomaticContainmentStatus = status.AutomaticContainmentAvailable
                    ? "Otomatik müdahale uygulanabilir; anahtar kayıtlı tercihinizi belirler."
                    : "Otomatik müdahale bu pilotta kapalı; tespit ve uyarılar devam eder.";
                AutoQuarantineThreshold = Math.Clamp(status.AutoQuarantineThreshold, 0, 100);
                if (_settingsService != null)
                {
                    var settings = _settingsService.Current;
                    if (IsProtectionStatusVerified)
                    {
                        settings.IsFileProtectionEnabled = IsFileProtectionEnabled;
                        settings.IsRansomwareShieldEnabled = IsRansomwareShieldEnabled;
                        settings.IsNetworkProtectionEnabled = IsNetworkProtectionEnabled;
                    }
                    settings.ScanScheduleEnabled = ScanScheduleEnabled;
                    settings.IdleScanEnabled = IdleScanEnabled;
                    settings.IdleScanThresholdMinutes = IdleScanThresholdMinutes;
                    settings.IdleScanIntervalHours = IdleScanIntervalHours;
                    settings.SkipIdleScanOnBattery = SkipIdleScanOnBattery;
                    settings.ScheduledScanHour = ScheduledScanHour;
                    settings.ScheduledScanIntervalHours = GetScheduledScanIntervalHours();
                    settings.ScheduledScanDay = ScheduledScanDay;
                    settings.ScanResourceMode = SelectedResourceMode;
                    settings.EnableAutoQuarantine = EnableAutoQuarantine;
                    settings.AutoQuarantineThreshold = AutoQuarantineThreshold;
                }
                EvaluateProtectionWarning();
            }
            finally
            {
                _isApplyingServiceStatus = false;
            }
        }

        /// <summary>Saves local preferences and requests service application; IPC transport is not an acknowledged settings commit.</summary>
        [RelayCommand]
        public async Task SaveSettingsAsync()
        {
            if (_isLoadingSettings || _isApplyingServiceStatus) return;
            if (_settingsService == null)
            {
                await SendServiceSettingsAsync();
                return;
            }

            var s = _settingsService.Current;
            s.Theme = SelectedThemeMode;
            s.IsRealTimeMonitoringEnabled = IsRealTimeMonitoringEnabled;
            s.NotificationsEnabled = NotificationsEnabled;
            s.ScanScheduleEnabled = ScanScheduleEnabled;
            s.IdleScanEnabled = IdleScanEnabled;
            s.IdleScanThresholdMinutes = Math.Clamp(IdleScanThresholdMinutes, 1, 240);
            s.IdleScanIntervalHours = Math.Clamp(IdleScanIntervalHours, 1, 168);
            s.SkipIdleScanOnBattery = SkipIdleScanOnBattery;
            s.PerformanceSampleIntervalMs = SampleIntervalSeconds * 1000;
            // Protection ownership belongs to the service; saving unrelated UI preferences must not persist optimistic toggles.
            s.EnableAutoQuarantine = EnableAutoQuarantine;
            s.AutoQuarantineThreshold = Math.Clamp(AutoQuarantineThreshold, 0, 100);
            s.IsProcessMonitoringEnabled = IsProcessMonitoringEnabled;
            s.IsCloudReputationEnabled = IsCloudLookupEnabled;
            s.ScheduledScanHour = ScheduledScanHour;
            s.ScheduledScanDay = ScheduledScanDay;
            s.ScanResourceMode = SelectedResourceMode;
            s.ScheduledScanIntervalHours = GetScheduledScanIntervalHours();

            try { await _settingsService.SaveAsync(); }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Ayarlar diske kaydedilemedi.");
                StatusMessage = "Ayarlar kaydedilemedi: " + ex.Message;
                return;
            }
            StatusMessage = _ipcClient?.IsConnected == true
                ? "Yerel ayarlar kaydedildi; servis isteği hazırlanıyor."
                : "Yerel ayarlar kaydedildi. Arka plan hizmeti bağlı değil; zamanlayıcıya henüz uygulanmadı.";
            await SendServiceSettingsAsync();
        }

        private int GetScheduledScanIntervalHours() => SelectedScanPeriod switch
        {
            var p when p?.Contains("12 Saat") == true => 12,
            var p when p?.Contains("6 Saat") == true => 6,
            var p when p?.Contains("3 Saat") == true => 3,
            var p when p?.Contains("1 Saat") == true => 1,
            var p when p?.Contains("30 Dakika") == true => 0,
            _ => 24
        };

        /// <summary>Refreshes the persisted exclusion snapshot and presents detached rule copies; load failures are displayed rather than treated as an empty success.</summary>
        [RelayCommand]
        public async Task LoadExclusionsAsync()
        {
            if (_exclusionService == null) return;
            try
            {
                if (_exclusionService is IExclusionRefreshService refresher) await refresher.ReloadAsync();
                var items = await _exclusionService.GetAllExclusionsAsync();
                Exclusions.Clear();
                foreach (var item in items)
                {
                    Exclusions.Add(item);
                }
                HasNoExclusions = Exclusions.Count == 0;
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "İstisnalar yüklenirken hata oluştu.");
                StatusMessage = "İstisnalar yüklenirken hata oluştu: " + ex.Message;
            }
        }

        /// <summary>Lets the user explicitly select a broad folder exemption; protected roots are rejected and service refresh is requested separately.</summary>
        [RelayCommand]
        public async Task AddFolderExclusionAsync()
        {
            if (_exclusionService == null)
            {
                StatusMessage = "İstisna yönetimi kullanılamıyor; değişiklik yapılmadı.";
                return;
            }
            try
            {
                var dialog = new Microsoft.Win32.OpenFolderDialog
                {
                    Title = "İstisna Tutulacak Klasörü Seçin"
                };

                if (dialog.ShowDialog() == true && !string.IsNullOrWhiteSpace(dialog.FolderName))
                {
                    if (_exclusionService.IsRootOrSystemDirectory(dialog.FolderName))
                    {
                        _toastNotificationService?.ShowToast(
                            "⚠️ Geçersiz Klasör",
                            "Kritik sistem dizinleri (C:\\, Windows, Program Files) kökten istisna yapılamaz.",
                            "Warning");
                        return;
                    }

                    if (System.Windows.MessageBox.Show(
                        "Bu klasör ve altındaki gelecekte eklenecek dosyalar denetim dışında kalabilir. Yalnız güvendiğiniz dar kapsamlı bir klasör için kullanın. Devam edilsin mi?",
                        "Geniş kapsamlı istisna", System.Windows.MessageBoxButton.YesNo,
                        System.Windows.MessageBoxImage.Warning) != System.Windows.MessageBoxResult.Yes) return;

                    var entry = await _exclusionService.AddPathExclusionAsync(dialog.FolderName, includeSubdirectories: true, reason: "Kullanıcı tercihi");
                    Exclusions.Insert(0, entry);
                    HasNoExclusions = Exclusions.Count == 0;
                    await RefreshServiceExclusionsAsync();
                    _toastNotificationService?.ShowToast(
                        "İstisna Kaydedildi",
                        $"'{System.IO.Path.GetFileName(dialog.FolderName)}' klasör kuralı yerelde kaydedildi. {StatusMessage}",
                        "Warning");
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Klasör istisnası eklenirken hata oluştu.");
                _toastNotificationService?.ShowToast("Hata", ex.Message, "Danger");
            }
        }

        /// <summary>Creates a SHA-256-bound file exemption so a replacement at the same path cannot inherit the original content's rule.</summary>
        [RelayCommand]
        public async Task AddFileExclusionAsync()
        {
            if (_exclusionService == null)
            {
                StatusMessage = "İstisna yönetimi kullanılamıyor; değişiklik yapılmadı.";
                return;
            }
            try
            {
                var dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "İstisna Tutulacak Dosyayı Seçin",
                    Filter = "Tüm Dosyalar (*.*)|*.*|Uygulamalar (*.exe;*.dll)|*.exe;*.dll"
                };

                if (dialog.ShowDialog() == true && !string.IsNullOrWhiteSpace(dialog.FileName))
                {
                    string hash;
                    await using (var stream = new System.IO.FileStream(dialog.FileName, System.IO.FileMode.Open,
                        System.IO.FileAccess.Read, System.IO.FileShare.Read, 81920, useAsync: true))
                        hash = Convert.ToHexString(await System.Security.Cryptography.SHA256.HashDataAsync(stream));
                    var entry = await _exclusionService.AddSha256ExclusionAsync(hash,
                        reason: "Kullanıcı tercihi; içerik kimliği: " + System.IO.Path.GetFileName(dialog.FileName));
                    Exclusions.Insert(0, entry);
                    HasNoExclusions = Exclusions.Count == 0;
                    await RefreshServiceExclusionsAsync();
                    _toastNotificationService?.ShowToast(
                        "İçerik İstisnası Kaydedildi",
                        $"'{System.IO.Path.GetFileName(dialog.FileName)}' için SHA-256 kuralı kaydedildi; değişen dosyaya uygulanmaz. {StatusMessage}",
                        "Warning");
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Dosya istisnası eklenirken hata oluştu.");
                _toastNotificationService?.ShowToast("Hata", ex.Message, "Danger");
            }
        }

        /// <summary>Removes the persisted rule and requests refresh in the service; stale IDs are reloaded instead of reporting a false removal.</summary>
        [RelayCommand]
        public async Task RemoveExclusionAsync(AegisPC.Core.Models.ExclusionEntry? entry)
        {
            if (_exclusionService == null || entry == null) return;
            try
            {
                bool removed = await _exclusionService.RemoveExclusionAsync(entry.Id);
                if (removed)
                {
                    Exclusions.Remove(entry);
                    HasNoExclusions = Exclusions.Count == 0;
                    await RefreshServiceExclusionsAsync();
                    _toastNotificationService?.ShowToast(
                        "İstisna Kaldırıldı",
                        $"'{System.IO.Path.GetFileName(entry.Value) ?? entry.Value}' yerel istisna listesinden çıkarıldı. {StatusMessage}",
                        "Info");
                }
                else
                {
                    await LoadExclusionsAsync();
                    StatusMessage = "İstisna daha önce kaldırılmış veya değişmiş; liste yeniden yüklendi.";
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "İstisna kaldırılırken hata oluştu: {Id}", entry.Id);
                _toastNotificationService?.ShowToast("Hata", ex.Message, "Danger");
            }
        }

        [RelayCommand]
        public void ClearScanCache()
        {
            if (_scanCoordinator?.IsScanning == true || _fileHashMatcher?.IsScanActive == true)
            {
                Serilog.Log.Warning("Aktif tarama devam ederken önbellek temizleme işlemi reddedildi.");
                _toastNotificationService?.ShowToast("İşlem Reddedildi", "Aktif tarama devam ederken tarama önbelleği temizlenemez.", "Warning");
                return;
            }

            int count = _fileHashMatcher?.CachedEntriesCount ?? 0;
            _fileHashMatcher?.ClearCache();
            Serilog.Log.Information("Tarama önbelleği temizlendi. {Count} önbellek kaydı temizlendi.", count);
            _toastNotificationService?.ShowToast("Önbellek Temizlendi", $"{count} önbellek kaydı temizlendi.", "Success");
        }

        public void Dispose()
        {
            _settingsDisposed = true;
            _protectionStatusTimer?.Stop();
            AppThemeManager.ThemeChanged -= OnAppThemeChanged;
            if (_ipcClient != null) _ipcClient.StatusChanged -= ApplyServiceStatus;
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
