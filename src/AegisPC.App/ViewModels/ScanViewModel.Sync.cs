using System;
using System.IO;
using System.Windows;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AegisPC.App.ViewModels
{
    /// <summary>
    /// ScanViewModel'in IScanCoordinatorService ile iki yönlü senkronizasyonunu,
    /// tarama ilerleme güncellemelerini ve sonuç bildirimlerini yöneten partial parçası.
    /// </summary>
    public partial class ScanViewModel
    {
        private bool IsFindingVisible(SecurityFinding finding) => FindingVisibilityPolicy.IsVisible(finding,
            _settingsService?.GetSetting("ShowPotentiallyUnwantedToolFindings", false) == true);
        private int HiddenCurrentFindingCount() => _scanCoordinator?.CurrentFindings?.Count(f => !IsFindingVisible(f)) ?? 0;
        private static string FormatActiveResourceProfile(ScanProgress progress)
        {
            if (progress.EffectiveWorkerLimit <= 0) return progress.ResourceProfileName;
            return $"{progress.ResourceProfileName} • Etkin {progress.ActiveWorkers}/{progress.EffectiveWorkerLimit} • Bekleyen {progress.PendingFiles}";
        }

        #region 5 Adımlı Kontrol Listesi (Checklist) Göstergeleri
        /// <summary>
        /// 1. Aşama: Bellek ve başlangıç nesneleri taraması tamamlandı mı?
        /// </summary>
        [ObservableProperty]
        private bool isStep1Done;

        /// <summary>
        /// 2. Aşama: Sistem ve sürücü dosyaları denetimi tamamlandı mı?
        /// </summary>
        [ObservableProperty]
        private bool isStep2Done;

        /// <summary>
        /// 3. Aşama: Kullanıcı profili ve indirilen dosyalar taraması tamamlandı mı?
        /// </summary>
        [ObservableProperty]
        private bool isStep3Done;

        /// <summary>
        /// 4. Aşama: Heuristik ve derin PE analizi tamamlandı mı?
        /// </summary>
        [ObservableProperty]
        private bool isStep4Done;

        /// <summary>
        /// 5. Aşama: Sonuç raporlama ve temizleme aşaması etkin mi?
        /// </summary>
        [ObservableProperty]
        private bool isStep5Active = true;

        public bool IsStep1Active => IsScanning && !IsStep1Done;
        public bool IsStep2Active => IsScanning && IsStep1Done && !IsStep2Done;
        public bool IsStep3Active => IsScanning && IsStep2Done && !IsStep3Done;
        public bool IsStep4Active => IsScanning && IsStep3Done && !IsStep4Done;
        /// <summary>Marks only actual completed scan status, not an inferred subsystem completion.</summary>
        public bool IsStep5Done => _lastScanStatus == ScanStatus.Completed && ProgressPercentage >= 100;
        public bool IsStep2Pending => !IsStep2Done && !IsStep2Active;
        public bool IsStep3Pending => !IsStep3Done && !IsStep3Active;
        public bool IsStep4Pending => !IsStep4Done && !IsStep4Active;
        public bool IsStep5Pending => !IsStep5Done && !IsStep5Active;
        #endregion
        /// <summary>
        /// Arka planda veya bağımsız bir iş parçacığında çalışmakta olan tarayıcı koordinatörünün
        /// mevcut anlık durumunu UI arayüz modeli ile senkronize eder.
        /// </summary>
        public void SyncWithScanCoordinator()
        {
            if (_scanCoordinator == null) return;

            DispatchUi(() =>
            {
                IsScanning = _scanCoordinator.IsScanning;
                IsNotScanning = !_scanCoordinator.IsScanning;
                IsPaused = IsScanning && _scanCoordinator.IsPaused;
                if (IsScanning)
                {
                    _isCancellationRequested = _scanCoordinator.State == ScanState.Cancelling;
                    IsScanFinishedView = false;
                    OnPropertyChanged(nameof(CanControlScan));
                }
                ProgressPercentage = (int)_scanCoordinator.ProgressPercent;
                CurrentFile = _scanCoordinator.CurrentFile;
                ScannedCount = _scanCoordinator.ScannedFiles;
                ScannedItemsFormatted = $"{ScannedCount:N0}";
                if (_scanCoordinator.CurrentSession?.LatestProgress is { } lp)
                {
                    ScannedFromCache = lp.ScannedFromCache;
                    SkippedSignedClean = lp.SkippedSignedClean;
                    NewlyScanned = lp.NewlyScanned;
                    FailedCount = lp.FailedFiles;
                    TimedOutCount = lp.TimedOutFiles;
                    SkippedCount = lp.SkippedFiles;
                    ConfirmedMaliciousCount = lp.ConfirmedMaliciousCount;
                    SuspiciousReviewCount = lp.SuspiciousCount;
                    IsCpuTelemetryAvailable = lp.IsCpuTelemetryAvailable;
                    CpuUsagePercent = lp.CpuUsagePercent;
                    RamUsageMb = lp.RamUsageMb;
                    ActiveResourceProfileText = FormatActiveResourceProfile(lp);
                    ScannedBreakdownFormatted = $"{lp.ScannedFromCache:N0} önbellekten • {lp.SkippedSignedClean:N0} imzalı geçti • {lp.NewlyScanned:N0} yeni tarandı";
                }
                TotalCount = _scanCoordinator.TotalFiles;
                FindingsCount = Math.Max(0, _scanCoordinator.FindingsCount - HiddenCurrentFindingCount());
                DetectionsCount = FindingsCount;
                ScanStatusText = _scanCoordinator.StatusText;
                if (IsScanning && _isCancellationRequested)
                {
                    ScanStatusText = "İptal isteniyor; çalışan işler durduruluyor.";
                    RemainingEtaFormatted = "İptal bekleniyor";
                }

                if (IsScanning)
                {
                    if (_scanCoordinator.ElapsedTime > TimeSpan.Zero)
                    {
                        _engineElapsedTime = _scanCoordinator.ElapsedTime;
                        _lastEngineUpdateUtc = DateTime.UtcNow;
                        ScanDurationFormatted = FormatDuration(_scanCoordinator.ElapsedTime);
                    }
                    if (IsPaused) { _stopwatch.Stop(); _timer?.Stop(); }
                    else { if (!_stopwatch.IsRunning) _stopwatch.Start(); _timer?.Start(); }
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
            if (_isCancellationRequested || _scanCoordinator?.State == ScanState.Cancelling || _scanCoordinator?.State == ScanState.Cancelled) return;

            DispatchUi(() =>
            {
                if (_isCancellationRequested || _scanCoordinator?.State == ScanState.Cancelling || _scanCoordinator?.State == ScanState.Cancelled) return;

                if (!IsScanning)
                {
                    IsScanning = true;
                    IsNotScanning = false;
                    IsScanFinishedView = false;
                }

                ProgressPercentage = (int)p.ProgressPercent;
                CurrentFile = p.CurrentFile;
                ScannedCount = p.ScannedFiles;
                ScannedItemsFormatted = $"{ScannedCount:N0}";
                ScannedFromCache = p.ScannedFromCache;
                SkippedSignedClean = p.SkippedSignedClean;
                NewlyScanned = p.NewlyScanned;
                ScannedBreakdownFormatted = $"{p.ScannedFromCache:N0} önbellekten • {p.SkippedSignedClean:N0} imzalı geçti • {p.NewlyScanned:N0} yeni tarandı";
                TotalCount = p.TotalFiles;
                FindingsCount = Math.Max(0, p.FindingsCount - HiddenCurrentFindingCount());
                ConfirmedMaliciousCount = p.ConfirmedMaliciousCount;
                SuspiciousReviewCount = p.SuspiciousCount;
                DetectionsCount = FindingsCount;
                SkippedCount = p.SkippedFiles;
                FailedCount = p.FailedFiles;
                TimedOutCount = p.TimedOutFiles;
                CpuUsagePercent = p.CpuUsagePercent;
                IsCpuTelemetryAvailable = p.IsCpuTelemetryAvailable;
                RamUsageMb = p.RamUsageMb;
                ActiveResourceProfileText = FormatActiveResourceProfile(p);
                OnPropertyChanged(nameof(CpuAndRamFormatted));
                RemainingEtaFormatted = !string.IsNullOrEmpty(p.FormattedEta) 
                    ? p.FormattedEta 
                    : FormatEta(p.EstimatedRemainingSeconds, p.ScannedFiles, p.TotalFiles);

                if (!IsPaused)
                {
                    ScanStatusText = string.IsNullOrWhiteSpace(p.Phase)
                        ? $"{p.ScanType} taraması işleniyor..."
                        : p.Phase;
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
        /// Keeps legacy stage bindings unknown because percentage progress does not prove that a particular subsystem ran.
        /// </summary>
        /// <param name="pct">Geçerli tarama ilerleme yüzdesi (0-100).</param>
        private void UpdateChecklistSteps(int pct)
        {
            IsStep1Done = false;
            IsStep2Done = false;
            IsStep3Done = false;
            IsStep4Done = false;
            IsStep5Active = IsScanning;

            OnPropertyChanged(nameof(IsStep1Active));
            OnPropertyChanged(nameof(IsStep2Active));
            OnPropertyChanged(nameof(IsStep3Active));
            OnPropertyChanged(nameof(IsStep4Active));
            OnPropertyChanged(nameof(IsStep5Done));
            OnPropertyChanged(nameof(IsStep2Pending));
            OnPropertyChanged(nameof(IsStep3Pending));
            OnPropertyChanged(nameof(IsStep4Pending));
            OnPropertyChanged(nameof(IsStep5Pending));
        }

        /// <summary>
        /// Tarama işlemi tamamlandığında veya sonlandığında çağrılarak nihai bulguları,
        /// süre sayaçlarını ve Windows toast bildirimlerini hazırlar.
        /// </summary>
        /// <param name="result">Tarama sonucunda elde edilen dosya sayıları ve bulgu listesi.</param>
        private void OnScanCompleted(ScanResult result)
        {
            var findings = result.Findings ?? new System.Collections.Generic.List<SecurityFinding>();
            Services.ScanReportRecord? capturedReport = null;
            try
            {
                capturedReport = new Services.ScanReportRecord
                {
                    Result = System.Text.Json.JsonSerializer.Deserialize<ScanResult>(System.Text.Json.JsonSerializer.Serialize(result))
                        ?? throw new InvalidDataException("The final scan result could not be captured."),
                    ResourceProfile = ActiveResourceProfileText,
                    Actions = new System.Collections.Generic.Dictionary<string, string>(_confirmedActions, StringComparer.OrdinalIgnoreCase)
                };
                _lastReport = capturedReport;
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Could not capture final scan report");
                _lastReport = null;
                DispatchUi(() => ReportHistoryStatus = "Sonuç görüntülenebilir; rapor kopyası oluşturulamadı: " + ex.Message);
            }
            DispatchUi(() =>
            {
                int visibleCount = findings.Count(IsFindingVisible);
                ApplyFinalScanCounters(result, visibleCount);
                PopulateFinalFindings(findings);
                NotifyFinalScanStatus(result, visibleCount);
                IsScanFinishedView = true;
                OnPropertyChanged(nameof(ScanResultTitle));
                OnPropertyChanged(nameof(CleanStateTitle));
                OnPropertyChanged(nameof(CleanStateSubtitle));
            });
            if (_persistReportHistory && capturedReport != null) _ = PersistReportAsync(capturedReport);
        }

        private void ApplyFinalScanCounters(ScanResult result, int findingsCount)
        {
            IsScanning = false;
            IsNotScanning = true;
            IsPaused = false;
            _stopwatch.Stop();
            _timer?.Stop();
            OnPropertyChanged(nameof(PauseButtonText));
            TimeSpan elapsed = result.ElapsedMs > 0 ? TimeSpan.FromMilliseconds(result.ElapsedMs)
                : result.StartedAt != default && result.CompletedAt.HasValue && result.CompletedAt.Value > result.StartedAt ? result.CompletedAt.Value - result.StartedAt
                : _engineElapsedTime > TimeSpan.Zero ? _engineElapsedTime : _stopwatch.Elapsed;
            ScanDurationFormatted = FormatDuration(elapsed);
            _lastScanStatus = result.Status;
            _isCancellationRequested = result.Status == ScanStatus.Cancelled;
            if (_isCancellationRequested)
            {
                _isCancellationRequested = true;
                if (result.TotalFiles > 0 && result.ScannedFiles > 0)
                    ProgressPercentage = Math.Clamp((int)(((double)result.ScannedFiles / result.TotalFiles) * 100), 0, 99);
                RemainingEtaFormatted = "İptal edildi";
                CurrentFile = "İptal edildi";
            }
            else if (result.Status == ScanStatus.Completed)
            {
                ProgressPercentage = 100;
                RemainingEtaFormatted = string.Empty;
                CurrentFile = "Tamamlandı";
                IsStep5Active = false;
            }
            else
            {
                ProgressPercentage = Math.Min(99, ProgressPercentage);
                RemainingEtaFormatted = "Tarama başarısız";
                CurrentFile = result.FailureInfo is { } failure
                    ? $"Tarama başarısız: {failure.Stage} / {failure.Reason}; kayıt: {failure.CorrelationId}"
                    : "Tarama başarısız";
            }
            ScannedCount = result.ScannedFiles;
            ScannedItemsFormatted = $"{ScannedCount:N0}";
            TotalCount = result.TotalFiles;
            SkippedCount = result.SkippedFiles;
            FailedCount = result.FailedFiles;
            TimedOutCount = result.TimedOutFiles;
            FindingsCount = findingsCount;
            ConfirmedMaliciousCount = result.Findings.Count(f => f.RiskLevel == RiskLevel.ConfirmedMalicious);
            SuspiciousReviewCount = result.Findings.Count(f => f.RiskLevel is RiskLevel.Suspicious or RiskLevel.HighRisk);
            DetectionsCount = FindingsCount;
            OnPropertyChanged(nameof(IsStep5Done));
        }

        private void PopulateFinalFindings(System.Collections.Generic.IReadOnlyList<SecurityFinding> findings)
        {
            ScanFindings.Clear();
            ThreatResults.Clear();
            foreach (var finding in findings)
            {
                if (!IsFindingVisible(finding)) continue;
                if (finding.Status == FindingStatus.Resolved || finding.Status == FindingStatus.Ignored || finding.IsAllowlisted) continue;
                ScanFindings.Add(finding);
                ThreatResults.Add(new SelectableThreatModel
                {
                    IsSelected = true,
                    Name = !string.IsNullOrWhiteSpace(finding.ObjectName) ? finding.ObjectName : Path.GetFileName(finding.ObjectPath),
                    ThreatType = finding.Category.ToString(),
                    ObjectType = "Dosya / Güvenlik nesnesi",
                    Location = finding.ObjectPath,
                    ActionTaken = Services.ScanReportGenerator.DetermineActionTaken(finding, _confirmedActions.TryGetValue(finding.ObjectPath, out var action) ? action : null),
                    Finding = finding
                });
            }
            HasFindings = ScanFindings.Count > 0;
            HasNoFindings = ScanFindings.Count == 0;
        }

        private void NotifyFinalScanStatus(ScanResult result, int findingsCount)
        {
            if (result.Status == ScanStatus.Cancelled || _isCancellationRequested)
            {
                ScanStatusText = $"Tarama durduruldu. {result.ScannedFiles:N0} dosya incelendi; kapsam ve bulgular raporda korunur.";
                _toastService?.ShowToast("Tarama İptal Edildi", ScanStatusText, "Warning");
            }
            else if (result.Status == ScanStatus.Failed)
            {
                ScanStatusText = $"Tarama başarısız; {result.ScannedFiles:N0} dosya incelendi. Hata ve bulgular raporda korunur.";
                _toastService?.ShowToast("Tarama Başarısız", ScanStatusText, "Warning");
            }
            else if (findingsCount == 0)
            {
                bool partialCoverage = !result.Coverage.IsComplete || result.SkippedFiles > 0 || result.FailedFiles > 0 || result.TimedOutFiles > 0;
                int hidden = result.Findings.Count - findingsCount;
                ScanStatusText = $"{result.ScannedFiles:N0} dosya incelendi; gösterilen güvenlik bulgusu yok." +
                    (hidden > 0 ? $" {hidden} isteğe bağlı araç kaydı ham raporda korunur." : "") +
                    (partialCoverage ? " Kapsam eksik; ayrıntılar raporda." : " Bu sonuç güvenlik garantisi değildir.");
                _toastService?.ShowToast(partialCoverage ? "Tarama Kapsamı Eksik" : "Tarama Tamamlandı", ScanStatusText, partialCoverage ? "Warning" : "Success");
            }
            else
            {
                int quarantinedCount = _confirmedActions.Count(pair => pair.Value == "Karantinaya alındı");
                ScanStatusText = $"{findingsCount} güvenlik bulgusu; {ThreatResults.Count} açık öğe, {quarantinedCount} doğrulanmış karantina eylemi. Ayrıntılar raporda.";
                if (!result.Coverage.IsComplete || result.FailedFiles > 0 || result.TimedOutFiles > 0)
                    ScanStatusText += " Bazı dosyaların incelemesi eksik; güvenli kabul edilmediler.";
                _toastService?.ShowToast(quarantinedCount > 0 ? "Karantina Eylemi Doğrulandı" : "Güvenlik Bulguları Var", ScanStatusText, "Warning");
            }
        }
    }
}
