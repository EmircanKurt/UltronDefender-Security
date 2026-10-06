using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.App.Views;
using AegisPC.Contracts.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;

namespace AegisPC.App.ViewModels
{
    /// <summary>
    /// DashboardViewModel'in kullanıcı etkileşimlerini, hızlı tarama komutlarını,
    /// modal yönetimlerini ve tema/gezinme delegasyonlarını yöneten partial parçası.
    /// </summary>
    public partial class DashboardViewModel
    {
        /// <summary>Opens the local protection centre; the robot is not a chat or an independent enforcement authority.</summary>
        [RelayCommand]
        public void OpenUltronProtectionCentre() => AppNavigation.NavigateTo(typeof(UltronProtectionCentreView));
        // ═══════════════════════════════════════════════
        // INTERACTIVE COMMAND 1: RANSOMWARE REMEDIATION
        // ═══════════════════════════════════════════════

        /// <summary>
        /// Fidye kalkanı öneri kartının detay açıklamasını açıp kapatır.
        /// </summary>
        [RelayCommand]
        public void ToggleRansomwareDetails()
        {
            ShowRansomwareDetails = !ShowRansomwareDetails;
        }

        /// <summary>
        /// Fidye kalkanı durumunu (açık/kapalı) tersine çevirir.
        /// </summary>
        [RelayCommand]
        public void ToggleRansomwareProtection()
        {
            IsRansomwareEnabled = !IsRansomwareEnabled;
        }

        /// <summary>
        /// Fidye Kalkanı gelişmiş ayarlar penceresini (korumalı klasörler, izinli uygulamalar) açar.
        /// </summary>
        [RelayCommand]
        public void OpenRansomwareSettings()
        {
            RansomwareSettingsWindow.ShowOrActivate();
        }

        /// <summary>
        /// Eski uyumluluk: Fidye kalkanı eylemini tetikler veya ayarları açar.
        /// </summary>
        [RelayCommand]
        public void EnableRansomwareAction()
        {
            if (!IsRansomwareEnabled)
            {
                IsRansomwareEnabled = true;
            }
            else
            {
                OpenRansomwareSettings();
            }
        }

        // ═══════════════════════════════════════════════
        // INTERACTIVE COMMAND 2: QUICK SCAN
        // ═══════════════════════════════════════════════

        /// <summary>
        /// Devam eden veya sonlanan aktif tarayıcı penceresini ekranda öne getirir.
        /// </summary>
        [RelayCommand]
        public void OpenActiveScanWindow()
        {
            var scanVm = App.ServiceProvider?.GetService<ScanViewModel>();
            if (scanVm != null)
            {
                Views.ActiveScanWindow.ShowScanWindow(scanVm);
            }
        }

        /// <summary>
        /// Routes an explicitly requested quick scan through the scan view model so
        /// resource selection, state reset, and an already-running scan share one path.
        /// </summary>
        [RelayCommand]
        public async Task StartQuickScanAsync()
        {
            var scanVm = App.ServiceProvider?.GetService<ScanViewModel>();
            if (scanVm == null)
            {
                TriggerToast("Tarayıcı hizmeti hazır değil; tarama başlatılamadı.", "Warning");
                return;
            }

            try
            {
                await scanVm.StartQuickScanAsync();
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Dashboard quick scan request failed");
                TriggerToast($"Tarama sırasında hata: {ex.Message}", "Warning");
            }
        }

        /// <summary>
        /// Gerçek zamanlı korumayı kapatmak veya açmak için kullanıcı onayını alır ve durumunu günceller.
        /// </summary>
        [RelayCommand]
        public void ToggleRealTimeProtection()
        {
            if (_observedServiceStatus?.IsRealTimeEnabled == true &&
                _observedServiceStatus.Health?.IsFresh(DateTime.UtcNow) == true && _ipcClient?.IsConnected == true)
            {
                var res = MessageBox.Show(
                    "⚠️ DİKKAT: Gerçek Zamanlı Korumayı kapatmak bilgisayarınızı virüslere, fidye yazılımlarına ve korsan saldırılara karşı savunmasız bırakır.\n\nBu işlem Yönetici Onayı gerektirir. Yine de korumayı devre dışı bırakmak istiyor musunuz?",
                    "Ultron Defender - Yönetici Koruma Uyarısı",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (res == MessageBoxResult.Yes)
                {
                    _ = RequestProtectionCommandAsync(AegisPC.ServiceContracts.IpcMessages.ServiceCommandType.DisableProtection);
                }
            }
            else
            {
                _ = RequestProtectionCommandAsync(AegisPC.ServiceContracts.IpcMessages.ServiceCommandType.EnableProtection);
            }
        }

        // ═══════════════════════════════════════════════
        // INTERACTIVE COMMAND 5: DEVICE MODAL
        // ═══════════════════════════════════════════════

        /// <summary>
        /// Shows or hides local device information without changing protection state.
        /// </summary>
        [RelayCommand]
        public void ToggleDeviceModal()
        {
            ShowDeviceModal = !ShowDeviceModal;
        }

        // ═══════════════════════════════════════════════
        // INTERACTIVE COMMAND 6: QUICK ACTION SELECTOR (+)
        // ═══════════════════════════════════════════════

        /// <summary>
        /// Hızlı Eylem Seçici modal penceresini açar veya kapatır.
        /// </summary>
        [RelayCommand]
        public void ToggleQuickActionModal()
        {
            ShowQuickActionModal = !ShowQuickActionModal;
        }

        /// <summary>
        /// Belirtilen hedef sayfaya uygulama içi gezinmeyi tetikler.
        /// </summary>
        /// <param name="target">Hedef sayfa anahtarı (scan, security, ransomware, network, performance, quarantine, startup, settings).</param>
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
                    AppNavigation.NavigateTo(typeof(SettingsView));
                    break;
                case "ransomware":
                case "fidye":
                    AppNavigation.NavigateTo(typeof(SettingsView));
                    break;
                case "network":
                case "ag":
                    AppNavigation.NavigateTo(typeof(SettingsView));
                    break;
                case "performance":
                case "performans":
                    AppNavigation.NavigateTo(typeof(DashboardView));
                    break;
                case "quarantine":
                case "karantina":
                    AppNavigation.NavigateTo(typeof(QuarantineView));
                    break;
                case "startup":
                case "baslangic":
                    AppNavigation.NavigateTo(typeof(ProcessListView));
                    break;
                case "browser":
                case "tarayici":
                    AppNavigation.NavigateTo(typeof(BrowserSecurityView));
                    break;
                case "process":
                case "surec":
                    AppNavigation.NavigateTo(typeof(ProcessListView));
                    break;
                case "crash":
                case "cokme":
                    AppNavigation.NavigateTo(typeof(CrashAnalysisView));
                    break;
                case "settings":
                case "ayarlar":
                    AppNavigation.NavigateTo(typeof(SettingsView));
                    break;
                default:
                    AppNavigation.NavigateTo(typeof(DashboardView));
                    break;
            }
        }

        // ═══════════════════════════════════════════════
        // STARTUP SWEEP & THREAT DETAIL COMMANDS
        // ═══════════════════════════════════════════════

        /// <summary>
        /// Başlangıç güvenlik taramasını arka planda başlatır.
        /// </summary>
        [RelayCommand]
        public async Task StartStartupSweepAsync()
        {
            if (_startupSweepService != null && !IsStartupSweepRunning)
            {
                try
                {
                    var result = await _startupSweepService.RunSweepAsync();
                    if (result.FinalStatus == StartupSweepStatus.Busy)
                    {
                        (StartupSweepStatusText, StartupSweepBadgeColor) = GetStartupSweepSummary(result);
                        TriggerToast("Başka bir tarama sürüyor; başlangıç kontrolü başlatılmadı.", "Info");
                    }
                }
                catch (Exception ex)
                {
                    Serilog.Log.Warning(ex, "Startup sweep request failed");
                    StartupSweepStatusText = "Başlangıç kontrolü başlatılamadı";
                    StartupSweepBadgeColor = "#F5A623";
                    TriggerToast("Başlangıç kontrolü başlatılamadı.", "Warning");
                }
            }
        }

        /// <summary>
        /// Belirtilen başlangıç tehdit bulgusunun detay modalını açar.
        /// </summary>
        /// <param name="finding">İncelenecek tehdit bulgusu.</param>
        [RelayCommand]
        public void ViewThreatDetail(StartupSweepFinding? finding)
        {
            if (finding != null)
            {
                SelectedThreatFinding = finding;
                ShowThreatDetailModal = true;
            }
        }

        /// <summary>
        /// Tehdit detay modal penceresini kapatır.
        /// </summary>
        [RelayCommand]
        public void CloseThreatDetail()
        {
            ShowThreatDetailModal = false;
        }

        /// <summary>
        /// Karantinaya alınmış bir başlangıç tehdit dosyasını orijinal konumuna geri yükler.
        /// </summary>
        /// <param name="finding">Geri yüklenecek tehdit bulgusu.</param>
        [RelayCommand]
        public async Task RestoreThreatAsync(StartupSweepFinding? finding)
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
                        var reason = _quarantineService.LastError ?? "Geri yükleme başarısız oldu!";
                        TriggerToast(reason, "Warning");
                    }
                }
                else
                {
                    TriggerToast("Karantina kaydı bulunamadı.", "Warning");
                }
            }
        }

        /// <summary>
        /// Tespit edilen tehditleri akıllıca incelemek üzere ilgili sayfaya yönlendirir.
        /// </summary>
        [RelayCommand]
        public void ReviewThreats()
        {
            // 1. Eğer son taramadan kalan aktif, çözülmemiş bulgular varsa Aktif Tarama Penceresini / Tarama sayfasını aç
            var scanVm = App.ServiceProvider?.GetService<ScanViewModel>();
            bool hasScanFindings = (_scanCoordinator?.CurrentFindings != null && 
                                    _scanCoordinator.CurrentFindings.Any(f => f.Status == AegisPC.Core.Enums.FindingStatus.Active && !f.IsAllowlisted)) ||
                                   (scanVm?.ThreatResults != null && scanVm.ThreatResults.Any(f => f.Finding.Status == AegisPC.Core.Enums.FindingStatus.Active && !f.Finding.IsAllowlisted));

            if (hasScanFindings && scanVm != null)
            {
                Views.ActiveScanWindow.ShowScanWindow(scanVm);
                return;
            }

            // 2. Karantina veya Olay Merkezi kontrolü
            var quarantineVm = App.ServiceProvider?.GetService<QuarantineViewModel>() ?? QuarantineViewModel.Current;
            if (quarantineVm != null)
            {
                // Eğer Karantina kasası boş ama Olay Geçmişinde kayıt varsa, doğrudan Olaylar sekmesine yönlendir
                if (quarantineVm.QuarantinedItems.Count == 0 && quarantineVm.Incidents.Count > 0)
                {
                    var mainWindow = Application.Current?.MainWindow as MainWindow ?? MainWindow.Instance;
                    if (mainWindow != null)
                    {
                        mainWindow.NavigateToQuarantine(showIncidentsTab: true);
                        return;
                    }
                }
            }

            // 3. Genel Karantina sayfasına yönlendir
            var mw = Application.Current?.MainWindow as MainWindow ?? MainWindow.Instance;
            if (mw != null)
            {
                mw.NavigateToQuarantine(showIncidentsTab: false);
            }
            else
            {
                NavigateToTarget("quarantine");
            }

            // 4. Tehdit durumunu senkronize et
            _ = RefreshThreatStatusAsync();
        }

        /// <summary>
        /// Uygulamanın koyu (Dark) ve açık (Light) teması arasında anlık geçiş yapar.
        /// </summary>
        [RelayCommand]
        public void ToggleTheme()
        {
            AegisPC.App.Services.AppThemeManager.ToggleTheme();
            ThemeButtonText = AegisPC.App.Services.AppThemeManager.IsDarkMode ? "☀️ Gündüz Modu" : "🌙 Gece Modu";
        }
    }
}
