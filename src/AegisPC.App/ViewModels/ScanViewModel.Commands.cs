using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
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
        /// Opens the scanner or existing scan window without starting an unsolicited scan.
        /// </summary>
        [RelayCommand]
        public Task OpenActiveScanWindowAsync()
        {
            Views.ActiveScanWindow.ShowScanWindow(this);
            return Task.CompletedTask;
        }

        /// <summary>Opens actual per-user report history without starting a scan.</summary>
        [RelayCommand]
        public void OpenReports() => Views.ActiveScanWindow.ShowReportsWindow(this);

        /// <summary>Opens schedule settings shared with the application's settings page.</summary>
        [RelayCommand]
        public void OpenScheduler() => Views.ActiveScanWindow.ShowSchedulerWindow(this);

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
            if (_scanCoordinator?.IsScanning == true) return;
            _timer?.Stop();
            _stopwatch.Stop();
            IsScanning = false;
            IsNotScanning = true;
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
                _lastEngineUpdateUtc = DateTime.UtcNow;
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
                _isCancellationRequested = true;
                _stopwatch.Stop();
                _timer?.Stop();
                IsScanning = false;
                IsNotScanning = true;
                IsPaused = false;
                IsScanFinishedView = true;
                ScanStatusText = "Tarama kullanıcı tarafından durduruldu.";
                RemainingEtaFormatted = "İptal edildi";
                CurrentFile = "İptal edildi.";
                OnPropertyChanged(nameof(PauseButtonText));
                OnPropertyChanged(nameof(ScanResultTitle));
                OnPropertyChanged(nameof(CleanStateTitle));
                OnPropertyChanged(nameof(CleanStateSubtitle));

                _scanCoordinator.CancelScan();
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
                            item.ActionTaken = "Karantinaya alındı";
                            RecordConfirmedAction(item.Finding, item.ActionTaken);
                            item.Finding.Status = FindingStatus.Resolved;
                            if (_findingService != null) await _findingService.UpdateFindingAsync(item.Finding);
                            ThreatResults.Remove(item);
                            ScanFindings.Remove(item.Finding);
                            count++;
                        }
                    }
                    else
                    {
                        item.ActionTaken = "Dosya bulunamadı; karantina doğrulanmadı";
                    }
                }
                catch (Exception ex)
                {
                    Serilog.Log.Warning(ex, "Karantinaya alma sırasında hata oluştu: {Path}", item.Location);
                }
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

        /// <summary>Closes selected incident records without declaring their files trusted or excluding future scans.</summary>
        [RelayCommand]
        public async Task ResolveSelectedAsync()
        {
            int count = 0;
            foreach (var item in ThreatResults.Where(t => t.IsSelected).ToList())
            {
                if (_findingService == null)
                {
                    ScanStatusText = "Olay kayıt servisi hazır değil; bulgu kapatılmadı.";
                    continue;
                }
                var previousStatus = item.Finding.Status;
                try
                {
                    item.Finding.Status = FindingStatus.Resolved;
                    await _findingService.UpdateFindingAsync(item.Finding);
                    RecordConfirmedAction(item.Finding, "Olay kapatıldı (dosya güvenilir ilan edilmedi)");
                    ThreatResults.Remove(item);
                    ScanFindings.Remove(item.Finding);
                    count++;
                }
                catch (Exception ex)
                {
                    item.Finding.Status = previousStatus;
                    Serilog.Log.Warning(ex, "Could not close incident {FindingId}", item.Finding.Id);
                    ScanStatusText = "Olay kapatılamadı: " + ex.Message;
                }
            }
            RefreshFindingCounters();
            if (count > 0)
                _toastService?.ShowToast("Olay Kapatıldı", $"{count} olay kapatıldı. Dosyalar istisna yapılmadı; sonraki taramalar yine inceleyebilir.", "Information");
        }

        /// <summary>Persists a content-bound exclusion, or an explicitly confirmed path exclusion; absent services or failures never remove the finding.</summary>
        [RelayCommand]
        public async Task ExcludeFindingAsync(SelectableThreatModel? item)
        {
            if (item == null) return;
            if ((_exclusionService == null && _allowlistService == null) || string.IsNullOrWhiteSpace(item.Location))
            {
                ScanStatusText = "İstisna servisi veya dosya yolu hazır değil; bulgu kaldırılmadı.";
                _toastService?.ShowToast("İstisna Uygulanamadı", ScanStatusText, "Warning");
                return;
            }

            try
            {
                string? hash = item.Finding.SHA256;
                bool hasHash = hash?.Length == 64 && hash.All(Uri.IsHexDigit);
                if (_exclusionService != null && hasHash)
                {
                    var entry = await _exclusionService.AddSha256ExclusionAsync(hash!, reason: "User explicitly excluded this file content from scan results");
                    if (entry == null) throw new InvalidOperationException("The exclusion was not persisted.");
                }
                else if (_exclusionService != null)
                {
                    if (Application.Current == null || MessageBox.Show(
                        "Bu bulguda doğrulanmış SHA-256 yok. Yol istisnası, bu konuma daha sonra yerleştirilen farklı dosyaları da taramadan çıkarabilir.\n\nBu dosya yolunu yine de istisna yapmak istiyor musunuz?",
                        "Yol İstisnası Güvenlik Uyarısı", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
                    var entry = await _exclusionService.AddPathExclusionAsync(item.Location, includeSubdirectories: false, reason: "User confirmed a path exclusion without a content hash");
                    if (entry == null) throw new InvalidOperationException("The exclusion was not persisted.");
                }
                else if (_allowlistService != null && hasHash)
                {
                    await _allowlistService.AddToAllowlistAsync(new AllowlistEntry
                    {
                        FilePath = item.Location, FileName = item.Name, SHA256 = hash!,
                        Reason = "User explicitly excluded this file content from scan results", AddedBy = "User", IsActive = true
                    });
                }
                else
                {
                    ScanStatusText = "İçerik özeti veya güvenli istisna servisi yok; bulgu kaldırılmadı.";
                    return;
                }

                bool serviceSynchronized = await RefreshServiceExclusionsAsync();

                item.Finding.Status = FindingStatus.Ignored;
                item.Finding.IsAllowlisted = true;
                RecordConfirmedAction(item.Finding, hasHash ? "Kullanıcı SHA-256 istisnası" : "Kullanıcı yol istisnası");
                if (_findingService != null) await _findingService.UpdateFindingAsync(item.Finding);
                ThreatResults.Remove(item);
                ScanFindings.Remove(item.Finding);
                RefreshFindingCounters();
                ScanStatusText = serviceSynchronized ? "İstisna kaydedildi." : "İstisna yerelde kaydedildi; koruma servisine aktarım doğrulanamadı.";
                _toastService?.ShowToast(serviceSynchronized ? "İstisna Kaydedildi" : "İstisna Kısmen Uygulandı", ScanStatusText, serviceSynchronized ? "Success" : "Warning");
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Could not persist exclusion for {Path}", item.Location);
                ScanStatusText = "İstisna işlemi tamamlanamadı: " + ex.Message;
                _toastService?.ShowToast("İstisna Hatası", ScanStatusText, "Danger");
            }
        }

        private void RefreshFindingCounters()
        {
            FindingsCount = ThreatResults.Count;
            DetectionsCount = FindingsCount;
            HasFindings = FindingsCount > 0;
            HasNoFindings = FindingsCount == 0;
            OnPropertyChanged(nameof(CleanStateTitle));
            OnPropertyChanged(nameof(CleanStateSubtitle));
        }

        private async Task<bool> RefreshServiceExclusionsAsync()
        {
            if (_ipcClient == null) return true;
            if (!_ipcClient.IsConnected) return false;
            try
            {
                await _ipcClient.SendCommandAsync(new AegisPC.ServiceContracts.IpcMessages.ServiceCommand
                {
                    CommandType = AegisPC.ServiceContracts.IpcMessages.ServiceCommandType.UpdateSettings,
                    Payload = "{\"RefreshExclusions\":true}", Timestamp = DateTime.UtcNow
                });
                return true;
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Exclusion persisted locally but service refresh failed");
                return false;
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
                Views.ActiveScanWindow.ShowScanWindow(this);
                return;
            }

            // GÖREV 6: Hızlı Tarama veya Tam Tarama başlatıldığında kaynak profili seçimi
            if (scanType == ScanType.Quick || scanType == ScanType.Full)
            {
                bool rememberMode = _settingsService?.GetSetting("RememberScanResourceMode", false) ?? false;
                var configuredMode = _settingsService?.GetSetting("ScanResourceMode", ScanResourceMode.Auto) ?? ScanResourceMode.Auto;

                ScanResourceMode targetMode = configuredMode;

                if (!rememberMode && System.Windows.Application.Current != null)
                {
                    var dialog = new Views.ScanResourceSelectionDialog(configuredMode);
                    var mainWindow = System.Windows.Application.Current.MainWindow;
                    if (mainWindow != null && mainWindow.IsVisible)
                    {
                        dialog.Owner = mainWindow;
                    }

                    bool? res = dialog.ShowDialog();
                    if (res != true)
                    {
                        // Kullanıcı taramayı başlatmaktan vazgeçti
                        return;
                    }

                    targetMode = dialog.SelectedMode;

                    if (dialog.RememberChoice && _settingsService != null)
                    {
                        _settingsService.SetSetting("ScanResourceMode", targetMode);
                        _settingsService.SetSetting("RememberScanResourceMode", true);
                        await _settingsService.SaveAsync();
                    }
                }

                SelectedResourceMode = targetMode;

                if (_resourceManager != null)
                {
                    _resourceManager.SetMode(targetMode);
                    HardwareTuningText = _resourceManager.ActiveProfile.SummaryText;
                    ActiveResourceProfileText = _resourceManager.ActiveProfile.SummaryText;
                }
                else
                {
                    var p = ScanResourceProfile.CreateDefault(targetMode);
                    AegisPC.Security.Scanning.ScanQueueCoordinator.ActiveResourceSummary = p.SummaryText;
                    HardwareTuningText = p.SummaryText;
                    ActiveResourceProfileText = p.SummaryText;
                }
            }

            ResetScanState(scanType);

            Views.ActiveScanWindow.ShowScanWindow(this);

            await _scanCoordinator.StartScanAsync(scanType, customPath);
        }
    }
}
