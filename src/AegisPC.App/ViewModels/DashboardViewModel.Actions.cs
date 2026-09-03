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
        /// Hızlı sistem taramasını başlatır veya tarama zaten çalışıyorsa iptal eder.
        /// </summary>
        [RelayCommand]
        public async Task StartQuickScanAsync()
        {
            if (_scanCoordinator == null) return;

            if (_scanCoordinator.IsScanning)
            {
                _scanCoordinator.CancelScan();
                IsScanning = false;
                QuickScanButtonText = "TARAMAYI BAŞLAT";
                ProtectionStatusText = "GÜVENDESİNİZ";
                ProtectionBadgeText = "GERÇEK ZAMANLI KORUMA AKTİF";
                ProtectionStatusColor = "#4CAF50";
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
            ProtectionStatusColor = "#2196F3";

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

        /// <summary>
        /// Gerçek zamanlı korumayı kapatmak veya açmak için kullanıcı onayını alır ve durumunu günceller.
        /// </summary>
        [RelayCommand]
        public void ToggleRealTimeProtection()
        {
            if (IsRealTimeProtectionActive)
            {
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
                    ProtectionStatusColor = "#C41E1E";
                    TriggerToast("⚠️ Gerçek Zamanlı Koruma kullanıcı tarafından kapatıldı!", "Warning");
                    UpdateProtectionUptime();
                }
            }
            else
            {
                IsRealTimeProtectionActive = true;
                ProtectionStatusText = "GÜVENDESİNİZ";
                ProtectionBadgeText = "GERÇEK ZAMANLI KORUMA AKTİF";
                ProtectionStatusColor = "#4CAF50";
                TriggerToast("🛡️ Gerçek Zamanlı Koruma başarıyla etkinleştirildi.", "Success");
                UpdateProtectionUptime();
            }
        }

        // ═══════════════════════════════════════════════
        // INTERACTIVE COMMAND 5: DEVICE / LICENSE MODAL
        // ═══════════════════════════════════════════════

        /// <summary>
        /// Cihaz ve lisans bilgi modal penceresini açar veya kapatır.
        /// </summary>
        [RelayCommand]
        public void ToggleDeviceModal()
        {
            ShowDeviceModal = !ShowDeviceModal;
        }

        /// <summary>
        /// Lisans anahtarını panoya (Clipboard) kopyalar.
        /// </summary>
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
                TriggerToast("Başlangıç Güvenlik Taraması başlatıldı...", "Info");
                await _startupSweepService.RunSweepAsync();
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
                        TriggerToast("Geri yükleme başarısız oldu!", "Warning");
                    }
                }
                else
                {
                    TriggerToast("Karantina kaydı bulunamadı.", "Warning");
                }
            }
        }

        /// <summary>
        /// Tespit edilen tehditleri incelemek üzere Karantina sayfasına yönlendirir.
        /// </summary>
        [RelayCommand]
        public void ReviewThreats()
        {
            NavigateToTarget("quarantine");
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
