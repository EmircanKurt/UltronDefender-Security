using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    /// <summary>
    /// ScanViewModel'in kullanıcı eylemleri, RelayCommand bağlayıcıları ve
    /// tarama koordinasyon kontrol komutlarını yöneten partial parçası.
    /// </summary>
    public partial class ScanViewModel
    {
        /// <summary>
        /// Kullanıcının devam eden veya yeni başlayan taramayı izlemesi için aktif tarama penceresini açar.
        /// </summary>
        [RelayCommand]
        public void OpenActiveScanWindow()
        {
            Views.ActiveScanWindow.ShowScanWindow(this);
        }

        /// <summary>
        /// Sistem başlangıç ve bellek alanlarını hedefleyen Hızlı Tarama (Quick Scan) işlemini başlatır.
        /// Zaten bir hızlı tarama çalışıyorsa aktif pencereyi öne getirir.
        /// </summary>
        [RelayCommand]
        public async Task StartQuickScanAsync()
        {
            if (_scanCoordinator != null && _scanCoordinator.IsScanning && _scanCoordinator.CurrentScanType == ScanType.Quick)
            {
                Views.ActiveScanWindow.ShowScanWindow(this);
                return;
            }
            await RunScanAsync(ScanType.Quick, string.Empty);
        }

        /// <summary>
        /// Tüm sabit disk bölümlerini kapsayan derinlemesine Tam Sistem Taraması (Full Scan) başlatır.
        /// Zaten bir tam tarama çalışıyorsa aktif pencereyi öne getirir.
        /// </summary>
        [RelayCommand]
        public async Task StartFullScanAsync()
        {
            if (_scanCoordinator != null && _scanCoordinator.IsScanning && _scanCoordinator.CurrentScanType == ScanType.Full)
            {
                Views.ActiveScanWindow.ShowScanWindow(this);
                return;
            }
            await RunScanAsync(ScanType.Full, string.Empty);
        }

        /// <summary>
        /// Kullanıcıdan klasör seçim penceresiyle bir dizin yolu alarak Özel Tarama (Custom Scan) başlatır.
        /// </summary>
        [RelayCommand]
        public async Task StartCustomScanAsync()
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog();
            if (dialog.ShowDialog() == true)
            {
                await RunScanAsync(ScanType.Custom, dialog.FolderName);
            }
        }

        /// <summary>
        /// Belirtilen belirli bir klasör veya dosya yolu için doğrudan Özel Tarama başlatır.
        /// </summary>
        /// <param name="path">Taranacak klasör veya dosya yolu.</param>
        public async Task StartCustomPathScanAsync(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            await RunScanAsync(ScanType.Custom, path);
        }

        /// <summary>
        /// Sonuç listesindeki tüm tehdit öğelerinin seçim kutularını topluca işaretler veya kaldırır.
        /// </summary>
        [RelayCommand]
        public void ToggleSelectAll()
        {
            IsAllSelected = !IsAllSelected;
            foreach (var item in ThreatResults)
            {
                item.IsSelected = IsAllSelected;
            }
        }

        /// <summary>
        /// Tarama sonuçları görünümünü kapatır ve tarayıcı durumunu başlangıç konumuna sıfırlar.
        /// </summary>
        [RelayCommand]
        public void CloseResults()
        {
            IsScanFinishedView = false;
            ScanFindings.Clear();
            ThreatResults.Clear();
            HasFindings = false;
            HasNoFindings = true;
            ScanStatusText = "Taramaya hazır.";
        }

        /// <summary>
        /// Devam eden taramayı geçici olarak duraklatır veya duraklatılmış taramayı sürdürür.
        /// </summary>
        [RelayCommand]
        public void TogglePauseResume()
        {
            if (_scanCoordinator == null || !IsScanning) return;

            if (IsPaused)
            {
                _scanCoordinator.ResumeScan();
                IsPaused = false;
                _stopwatch.Start();
                _timer?.Start();
                ScanStatusText = "Tarama devam ediyor...";
            }
            else
            {
                _scanCoordinator.PauseScan();
                IsPaused = true;
                _stopwatch.Stop();
                _timer?.Stop();
                ScanStatusText = "Tarama duraklatıldı.";
            }
            OnPropertyChanged(nameof(PauseButtonText));
        }

        /// <summary>
        /// Devam eden tarama işlemini derhal iptal eder ve sayaçları durdurur.
        /// </summary>
        [RelayCommand]
        public void CancelScan()
        {
            if (_scanCoordinator != null)
            {
                _scanCoordinator.CancelScan();
                _stopwatch.Stop();
                _timer?.Stop();
                IsScanning = false;
                IsNotScanning = true;
                IsPaused = false;
                IsScanFinishedView = false;
                ScanStatusText = "Tarama iptal edildi.";
                OnPropertyChanged(nameof(PauseButtonText));
            }
        }

        /// <summary>
        /// Kullanıcı tarafından sonuç tablosunda işaretlenmiş olan tüm tehdit dosyalarını
        /// AES-256 Karantina Kasasına kilitler ve bulgu durumlarını günceller.
        /// </summary>
        [RelayCommand]
        public async Task QuarantineSelectedAsync()
        {
            if (_quarantineService == null || ThreatResults.Count == 0) return;

            var selectedItems = ThreatResults.Where(t => t.IsSelected).ToList();
            int count = 0;

            foreach (var item in selectedItems)
            {
                try
                {
                    if (File.Exists(item.Location))
                    {
                        bool ok = await _quarantineService.QuarantineFileAsync(item.Location, item.Finding.Title);
                        if (ok)
                        {
                            item.Finding.Status = FindingStatus.Resolved;
                            if (_findingService != null) await _findingService.UpdateFindingAsync(item.Finding);
                            ThreatResults.Remove(item);
                            ScanFindings.Remove(item.Finding);
                            count++;
                        }
                    }
                    else
                    {
                        ThreatResults.Remove(item);
                    }
                }
                catch { }
            }

            FindingsCount = ThreatResults.Count;
            DetectionsCount = FindingsCount;
            HasFindings = FindingsCount > 0;
            HasNoFindings = FindingsCount == 0;

            if (count > 0)
            {
                _toastService?.ShowToast(
                    "Tehdit Kaldırıldı",
                    $"{count} adet zararlı tehdit başarıyla Karantina Kasasına kilitlendi.",
                    "Success");
            }

            if (ThreatResults.Count == 0)
            {
                IsScanFinishedView = false;
            }
        }

        /// <summary>
        /// Belirtilen tarama türünü yapılandırıp sayaçları sıfırlayarak tarayıcı koordinatörünü çalıştırır.
        /// </summary>
        /// <param name="scanType">Çalıştırılacak tarama türü (Hızlı, Tam, Özel).</param>
        /// <param name="customPath">Özel tarama için hedef klasör yolu (opsiyonel).</param>
        private async Task RunScanAsync(ScanType scanType, string customPath)
        {
            if (_scanCoordinator == null)
            {
                ScanStatusText = "Tarayıcı servisi hazır değil.";
                return;
            }

            if (IsScanning || _scanCoordinator.IsScanning)
            {
                _scanCoordinator.CancelScan();
                await Task.Delay(100);
            }

            IsScanning = true;
            IsNotScanning = false;
            IsScanFinishedView = false;
            IsPaused = false;
            ProgressPercentage = 0;
            ScannedCount = 0;
            ScannedItemsFormatted = "0";
            FindingsCount = 0;
            DetectionsCount = 0;
            ScanFindings.Clear();
            ThreatResults.Clear();
            HasFindings = false;
            HasNoFindings = true;
            ScanStatusText = $"{scanType} taraması işleniyor...";

            _stopwatch.Restart();
            _timer?.Start();

            Views.ActiveScanWindow.ShowScanWindow(this);

            await _scanCoordinator.StartScanAsync(scanType, customPath);
        }
    }
}
