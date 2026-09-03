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
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
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
                if (!IsPaused)
                {
                    ScanStatusText = $"{p.ScanType} taraması işleniyor...";
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

                var elapsed = _stopwatch.Elapsed;
                ScanDurationFormatted = $"{elapsed.Minutes}d {elapsed.Seconds:D2}s";

                ProgressPercentage = 100;
                ScannedCount = result.ScannedFiles;
                ScannedItemsFormatted = $"{ScannedCount:N0}";
                TotalCount = result.TotalFiles;
                FindingsCount = result.Findings.Count;
                DetectionsCount = FindingsCount;

                IsStep1Done = true;
                IsStep2Done = true;
                IsStep3Done = true;
                IsStep4Done = true;
                IsStep5Active = false;

                ScanFindings.Clear();
                ThreatResults.Clear();

                if (result.Findings != null)
                {
                    foreach (var f in result.Findings)
                    {
                        ScanFindings.Add(f);

                        string cat = f.RiskLevel == RiskLevel.ConfirmedMalicious ? "Kötücül Yazılım" :
                                     f.RiskLevel == RiskLevel.HighRisk ? "Truva Atı / Riskli Kod" : "RiskWare.Agent";

                        ThreatResults.Add(new SelectableThreatModel
                        {
                            IsSelected = true,
                            Name = !string.IsNullOrWhiteSpace(f.ObjectName) ? f.ObjectName : Path.GetFileName(f.ObjectPath),
                            ThreatType = cat,
                            ObjectType = f.ObjectPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? "Bellek / Yürütülebilir" : "Dosya",
                            Location = f.ObjectPath,
                            Finding = f
                        });
                    }
                }

                HasFindings = ScanFindings.Count > 0;
                HasNoFindings = ScanFindings.Count == 0;
                IsScanFinishedView = true;

                if (HasNoFindings)
                {
                    ScanStatusText = $"Tarama tamamlandı. {result.ScannedFiles:N0} dosya incelendi, sistem tamamen temiz.";
                    _toastService?.ShowToast(
                        "Sistem Güvende",
                        $"Tehdit taraması tamamlandı: {result.ScannedFiles:N0} dosya incelendi, herhangi bir virüse rastlanmadı.",
                        "Success");
                }
                else
                {
                    ScanStatusText = $"Tehdit Taraması Sonuçları: {ScanFindings.Count} adet zararlı tespit edildi.";
                    _toastService?.ShowToast(
                        "Tehdit Kaldırıldı ve Karantinaya Alındı",
                        $"{ScanFindings.Count} adet zararlı yazılım tespit edildi ve karantinaya kilitlendi.",
                        "Danger");
                }
            });
        }
    }
}
