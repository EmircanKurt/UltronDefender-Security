using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
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
        /// Kullanıcı tarafından sonuç tablosunda işaretlenmiş olan tüm tehdit dosyalarını
        /// "Çözüldü" olarak işaretler, güvenli listeye ekler ve sonraki taramalardan muaf tutar.
        /// </summary>
        [RelayCommand]
        public async Task ResolveSelectedAsync()
        {
            if (ThreatResults.Count == 0) return;

            var selectedItems = ThreatResults.Where(t => t.IsSelected).ToList();
            if (selectedItems.Count == 0) return;

            int count = 0;

            foreach (var item in selectedItems)
            {
                try
                {
                    item.Finding.Status = FindingStatus.Resolved;
                    item.Finding.IsAllowlisted = true;

                    if (_findingService != null)
                    {
                        await _findingService.UpdateFindingAsync(item.Finding);
                    }

                    if (_allowlistService != null && !string.IsNullOrEmpty(item.Location))
                    {
                        var entry = new AllowlistEntry
                        {
                            FilePath = item.Location,
                            FileName = item.Name,
                            SHA256 = item.Finding.SHA256 ?? string.Empty,
                            Reason = "Kullanıcı tarafından çözüldü olarak işaretlendi.",
                            AddedBy = "Kullanıcı (Çözüldü)",
                            AddedAt = DateTime.UtcNow,
                            IsActive = true
                        };
                        await _allowlistService.AddToAllowlistAsync(entry);
                    }

                    if (_settingsService != null)
                    {
                        try
                        {
                            var dismissed = _settingsService.GetSetting<List<string>>("DismissedIncidentIds", new List<string>()) ?? new List<string>();
                            if (!string.IsNullOrEmpty(item.Location) && !dismissed.Contains(item.Location, StringComparer.OrdinalIgnoreCase))
                            {
                                dismissed.Add(item.Location);
                            }
                            _settingsService.SetSetting("DismissedIncidentIds", dismissed);
                            await _settingsService.SaveAsync();
                        }
                        catch { }
                    }

                    ThreatResults.Remove(item);
                    ScanFindings.Remove(item.Finding);
                    count++;
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
                    "Tehdit Çözüldü Olarak İşaretlendi",
                    $"{count} adet öğe çözüldü olarak işaretlendi ve sonraki taramalardan hariç tutuldu.",
                    "Success");
            }

            if (ThreatResults.Count == 0)
            {
                OnPropertyChanged(nameof(CleanStateTitle));
                OnPropertyChanged(nameof(CleanStateSubtitle));
            }
        }

        /// <summary>
        /// Tamamlanan tarama sonuçlarını, istatistiklerini ve tespit edilen bulguları
        /// metin (.txt) veya JSON (.json) formatında dışa aktarır.
        /// </summary>
        [RelayCommand]
        public async Task ExportScanReportAsync()
        {
            try
            {
                var sfd = new Microsoft.Win32.SaveFileDialog
                {
                    Title = "Tarama Raporunu Dışa Aktar",
                    FileName = $"UltronDefender_ScanReport_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                    Filter = "Metin Raporu (*.txt)|*.txt|JSON Raporu (*.json)|*.json|Tüm Dosyalar (*.*)|*.*",
                    DefaultExt = ".txt"
                };

                if (sfd.ShowDialog() != true)
                    return;

                string filePath = sfd.FileName;
                bool isJson = filePath.EndsWith(".json", StringComparison.OrdinalIgnoreCase);

                var scanType = _scanCoordinator?.CurrentScanType ?? ScanType.Quick;

                if (isJson)
                {
                    var reportObj = new
                    {
                        Application = "Ultron Defender Total Security (AegisPC)",
                        ExportTimestamp = DateTime.UtcNow,
                        ScanType = scanType.ToString(),
                        Duration = ScanDurationFormatted,
                        ScannedFiles = ScannedCount,
                        TotalFiles = TotalCount,
                        SkippedFiles = SkippedCount,
                        FailedFiles = FailedCount,
                        TimedOutFiles = TimedOutCount,
                        ResourceProfile = ActiveResourceProfileText,
                        FindingsCount = FindingsCount,
                        Findings = ScanFindings.Select(f => new
                        {
                            FindingId = f.Id,
                            f.Title,
                            f.Description,
                            f.ObjectPath,
                            RiskLevel = f.RiskLevel.ToString(),
                            f.RiskScore,
                            DetectedAt = f.CreatedAt,
                            Status = f.Status.ToString()
                        }).ToList()
                    };

                    string jsonText = System.Text.Json.JsonSerializer.Serialize(reportObj, new System.Text.Json.JsonSerializerOptions
                    {
                        WriteIndented = true
                    });

                    await File.WriteAllTextAsync(filePath, jsonText);
                }
                else
                {
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("================================================================================");
                    sb.AppendLine("            ULTRON DEFENDER TOTAL SECURITY - GÜVENLİK TARAMA RAPORU             ");
                    sb.AppendLine("================================================================================");
                    sb.AppendLine($"Rapor Tarihi       : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    sb.AppendLine($"Tarama Türü        : {scanType}");
                    sb.AppendLine($"Tarama Süresi      : {ScanDurationFormatted}");
                    sb.AppendLine($"Kaynak Profili     : {ActiveResourceProfileText}");
                    sb.AppendLine($"İncelenen Dosyalar : {ScannedCount:N0}");
                    sb.AppendLine($"Atlanan Dosyalar   : {SkippedCount:N0}");
                    sb.AppendLine($"Hatalı / Zaman Aşımı: {FailedCount:N0} / {TimedOutCount:N0}");
                    sb.AppendLine($"Durum              : {(HasFindings ? $"⚠️ {FindingsCount} Tehdit Tespit Edildi" : "✓ Temiz - Sistem Güvende")}");
                    sb.AppendLine("--------------------------------------------------------------------------------");
                    sb.AppendLine();

                    if (ScanFindings.Count > 0)
                    {
                        sb.AppendLine($"[TESPİT EDİLEN TEHDİTLER ({ScanFindings.Count})]");
                        int index = 1;
                        foreach (var f in ScanFindings)
                        {
                            sb.AppendLine($"{index}. Tehdit Başlığı : {f.Title}");
                            sb.AppendLine($"   Konum           : {f.ObjectPath}");
                            sb.AppendLine($"   Risk Seviyesi   : {f.RiskLevel} (Skor: {f.RiskScore}/100)");
                            sb.AppendLine($"   Durum           : {f.Status}");
                            sb.AppendLine($"   Açıklama        : {f.Description}");
                            sb.AppendLine();
                            index++;
                        }
                    }
                    else
                    {
                        sb.AppendLine("Herhangi bir zararlı yazılım veya tehdit tespit edilmedi.");
                        sb.AppendLine("Sistem koruması güncel ve güvenlidir.");
                    }

                    sb.AppendLine("================================================================================");
                    sb.AppendLine("Ultron Defender Total Security | Gelişmiş Tehdit Savunma Motoru");

                    await File.WriteAllTextAsync(filePath, sb.ToString());
                }

                _toastService?.ShowToast(
                    "Rapor Kaydedildi",
                    $"Tarama raporu başarıyla kaydedildi: {Path.GetFileName(filePath)}",
                    "Success");
            }
            catch (Exception ex)
            {
                _toastService?.ShowToast("Rapor Hatası", $"Rapor kaydedilemedi: {ex.Message}", "Danger");
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
                var configuredMode = _settingsService?.GetSetting("ScanResourceMode", ScanResourceMode.Balanced) ?? ScanResourceMode.Balanced;
                if (configuredMode == ScanResourceMode.Auto) configuredMode = ScanResourceMode.Balanced;

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
                        _ = _settingsService.SaveAsync();
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
