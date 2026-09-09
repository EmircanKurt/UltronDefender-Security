using System;
using System.IO;
using System.Windows;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.App.ViewModels
{
    /// <summary>
    /// ScanViewModel'in IScanCoordinatorService ile iki yönlü senkronizasyonunu,
    /// tarama ilerleme güncellemelerini ve sonuç bildirimlerini yöneten partial parçası.
    /// </summary>
    public partial class ScanViewModel
    {
        /// <summary>
        /// Arka planda veya bağımsız bir iş parçacığında çalışmakta olan tarayıcı koordinatörünün
        /// mevcut anlık durumunu UI arayüz modeli ile senkronize eder.
        /// </summary>
        public void SyncWithScanCoordinator()
        {
            if (_scanCoordinator == null) return;

            Application.Current?.Dispatcher?.Invoke(() =>
            {
                IsScanning = _scanCoordinator.IsScanning;
                IsNotScanning = !_scanCoordinator.IsScanning;
                ProgressPercentage = (int)_scanCoordinator.ProgressPercent;
                CurrentFile = _scanCoordinator.CurrentFile;
                ScannedCount = _scanCoordinator.ScannedFiles;
                ScannedItemsFormatted = $"{ScannedCount:N0}";
                TotalCount = _scanCoordinator.TotalFiles;
                FindingsCount = _scanCoordinator.FindingsCount;
                DetectionsCount = FindingsCount;
                ScanStatusText = _scanCoordinator.StatusText;

                if (IsScanning)
                {
                    if (_scanCoordinator.ElapsedTime > TimeSpan.Zero)
                    {
                        _engineElapsedTime = _scanCoordinator.ElapsedTime;
                        _lastEngineUpdateUtc = DateTime.UtcNow;
                        ScanDurationFormatted = FormatDuration(_scanCoordinator.ElapsedTime);
                    }
                    if (!_stopwatch.IsRunning) _stopwatch.Start();
                    _timer?.Start();
                }

                UpdateChecklistSteps(ProgressPercentage);
            });
        }

        /// <summary>
        /// Tarayıcı servisinden gelen periyodik ilerleme bildirimini işler ve UI durumunu günceller.
        /// </summary>
        /// <param name="p">Anlık tarama ilerleme metrikleri.</param>
        private void OnScanProgressChanged(ScanProgress p)
        {
            if (_isCancellationRequested || !IsScanning) return;

            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                if (_isCancellationRequested || !IsScanning) return;

                IsScanning = true;
                IsNotScanning = false;
                IsScanFinishedView = false;
                ProgressPercentage = (int)p.ProgressPercent;
                CurrentFile = p.CurrentFile;
                ScannedCount = p.ScannedFiles;
                ScannedItemsFormatted = $"{ScannedCount:N0}";
                TotalCount = p.TotalFiles;
                FindingsCount = p.FindingsCount;
                DetectionsCount = FindingsCount;
                SkippedCount = p.SkippedFiles;
                FailedCount = p.FailedFiles;
                TimedOutCount = p.TimedOutFiles;
                CpuUsagePercent = p.CpuUsagePercent;
                RamUsageMb = p.RamUsageMb;
                ActiveResourceProfileText = p.ResourceProfileName;
                OnPropertyChanged(nameof(CpuAndRamFormatted));
                RemainingEtaFormatted = !string.IsNullOrEmpty(p.FormattedEta) 
                    ? p.FormattedEta 
                    : FormatEta(p.EstimatedRemainingSeconds, p.ScannedFiles, p.TotalFiles);

                if (!IsPaused)
                {
                    ScanStatusText = $"{p.ScanType} taraması işleniyor...";
                }

                if (p.ElapsedTime > TimeSpan.Zero)
                {
                    _engineElapsedTime = p.ElapsedTime;
                    _lastEngineUpdateUtc = DateTime.UtcNow;
                    ScanDurationFormatted = FormatDuration(p.ElapsedTime);
                }

                if (!_stopwatch.IsRunning && !IsPaused)
                {
                    _stopwatch.Start();
                    _timer?.Start();
                }

                UpdateChecklistSteps(ProgressPercentage);
            });
        }

        /// <summary>
        /// Yüzdelik ilerleme durumuna göre 5 adımlı checklist (kontrol listesi) aşama göstergelerini günceller.
        /// </summary>
        /// <param name="pct">Geçerli tarama ilerleme yüzdesi (0-100).</param>
        private void UpdateChecklistSteps(int pct)
        {
            IsStep1Done = pct >= 8;
            IsStep2Done = pct >= 20;
            IsStep3Done = pct >= 35;
            IsStep4Done = pct >= 50;
            IsStep5Active = pct < 100;
        }

        /// <summary>
        /// Tarama işlemi tamamlandığında veya sonlandığında çağrılarak nihai bulguları,
        /// süre sayaçlarını ve Windows toast bildirimlerini hazırlar.
        /// </summary>
        /// <param name="result">Tarama sonucunda elde edilen dosya sayıları ve bulgu listesi.</param>
        private void OnScanCompleted(ScanResult result)
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                IsScanning = false;
                IsNotScanning = true;
                IsPaused = false;
                _stopwatch.Stop();
                _timer?.Stop();
                OnPropertyChanged(nameof(PauseButtonText));

                TimeSpan elapsed;
                if (result.ElapsedMs > 0)
                {
                    elapsed = TimeSpan.FromMilliseconds(result.ElapsedMs);
                }
                else if (result.CompletedAt.HasValue && result.CompletedAt.Value > result.StartedAt)
                {
                    elapsed = result.CompletedAt.Value - result.StartedAt;
                }
                else if (_engineElapsedTime > TimeSpan.Zero)
                {
                    elapsed = _engineElapsedTime;
                }
                else
                {
                    elapsed = _stopwatch.Elapsed;
                }

                ScanDurationFormatted = FormatDuration(elapsed);

                bool wasCancelled = result.Status == ScanStatus.Cancelled || _isCancellationRequested;

                if (wasCancelled)
                {
                    _isCancellationRequested = true;
                    if (result.TotalFiles > 0 && result.ScannedFiles > 0)
                    {
                        ProgressPercentage = Math.Clamp((int)(((double)result.ScannedFiles / result.TotalFiles) * 100), 0, 99);
                    }
                    RemainingEtaFormatted = "İptal edildi";
                    CurrentFile = "İptal edildi";
                }
                else
                {
                    ProgressPercentage = 100;
                    RemainingEtaFormatted = string.Empty;
                    CurrentFile = "Tamamlandı";
                    IsStep1Done = true;
                    IsStep2Done = true;
                    IsStep3Done = true;
                    IsStep4Done = true;
                    IsStep5Active = false;
                }

                ScannedCount = result.ScannedFiles;
                ScannedItemsFormatted = $"{ScannedCount:N0}";
                TotalCount = result.TotalFiles;
                FindingsCount = result.Findings.Count;
                DetectionsCount = FindingsCount;

                ScanFindings.Clear();
                ThreatResults.Clear();

                if (result.Findings != null)
                {
                    foreach (var f in result.Findings)
                    {
                        if (f.Status == FindingStatus.Resolved || f.IsAllowlisted)
                        {
                            continue;
                        }

                        ScanFindings.Add(f);

                        string cat = f.RiskLevel == RiskLevel.ConfirmedMalicious ? "Kötücül Yazılım" :
                                     f.RiskLevel == RiskLevel.HighRisk ? "Truva Atı / Riskli Kod" : "RiskWare.Agent";

                        bool isQuarantined = f.Status == FindingStatus.Resolved || f.RiskScore >= 85;

                        ThreatResults.Add(new SelectableThreatModel
                        {
                            IsSelected = !isQuarantined,
                            Name = !string.IsNullOrWhiteSpace(f.ObjectName) ? f.ObjectName : Path.GetFileName(f.ObjectPath),
                            ThreatType = cat,
                            ObjectType = f.ObjectPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? "Bellek / Yürütülebilir" : "Dosya",
                            Location = f.ObjectPath,
                            ActionTaken = isQuarantined ? "Karantinaya alındı" : "Uyarıldı",
                            Finding = f
                        });
                    }
                }

                HasFindings = ScanFindings.Count > 0;
                HasNoFindings = ScanFindings.Count == 0;
                IsScanFinishedView = true;

                if (result.Status == ScanStatus.Cancelled || _isCancellationRequested)
                {
                    _isCancellationRequested = true;
                    ScanStatusText = $"Tarama kullanıcı tarafından durduruldu. {result.ScannedFiles:N0} dosya incelendi.";
                    _toastService?.ShowToast(
                        "Tarama İptal Edildi",
                        $"Tehdit taraması durduruldu: {result.ScannedFiles:N0} dosya incelendi.",
                        "Warning");
                }
                else if (HasNoFindings)
                {
                    ScanStatusText = $"Tarama tamamlandı. {result.ScannedFiles:N0} dosya incelendi, sistem tamamen temiz.";
                    _toastService?.ShowToast(
                        "Sistem Güvende",
                        $"Tehdit taraması tamamlandı: {result.ScannedFiles:N0} dosya incelendi, herhangi bir virüse rastlanmadı.",
                        "Success");
                }
                else
                {
                    int quarantinedCount = ThreatResults.Count(t => t.ActionTaken == "Karantinaya alındı");
                    if (quarantinedCount > 0)
                    {
                        ScanStatusText = $"Tehdit Taraması: {quarantinedCount} tehdit karantinaya alındı, {ThreatResults.Count - quarantinedCount} uyarıldı.";
                        _toastService?.ShowToast(
                            "Tehdit Engellendi ve Karantinaya Alındı",
                            $"{quarantinedCount} adet zararlı tehdit başarıyla Karantina Kasasına kilitlendi.",
                            "Danger");
                    }
                    else
                    {
                        ScanStatusText = $"Tehdit Taraması: {ThreatResults.Count} adet şüpheli dosya uyarısı.";
                        _toastService?.ShowToast(
                            "Şüpheli Dosya Uyarısı",
                            $"{ThreatResults.Count} adet şüpheli dosya algılandı. Detaylar için Olay Merkezini inceleyin.",
                            "Warning");
                    }
                }

                OnPropertyChanged(nameof(ScanResultTitle));
                OnPropertyChanged(nameof(CleanStateTitle));
                OnPropertyChanged(nameof(CleanStateSubtitle));
            });
        }
    }
}
