using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.App.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels;

/// <summary>Loads per-user final scan history and exports immutable engine snapshots instead of mutable UI counters.</summary>
public partial class ScanViewModel
{
    private readonly ScanReportHistoryStore _reportHistoryStore;
    private readonly bool _persistReportHistory;
    private ScanReportRecord? _lastReport;
    private readonly System.Collections.Generic.Dictionary<string, string> _confirmedActions = new(StringComparer.OrdinalIgnoreCase);
    private AegisPC.Core.Enums.ScanStatus _lastScanStatus = AegisPC.Core.Enums.ScanStatus.Running;
    /// <summary>Lists up to 50 final results observed by this user's application; it is not complete service-wide history.</summary>
    public ObservableCollection<ScanReportRecord> ReportHistory { get; } = new();

    /// <summary>The historical result selected for export; null means that no history report is selected.</summary>
    [ObservableProperty] private ScanReportRecord? selectedReport;

    /// <summary>Explains loading or persistence failures without claiming that an unreadable history is empty.</summary>
    [ObservableProperty] private string reportHistoryStatus = "Rapor geçmişi henüz yüklenmedi.";

    /// <summary>Loads actual final results persisted for this user without starting a scan.</summary>
    [RelayCommand]
    public async Task RefreshReportsAsync()
    {
        try
        {
            var records = await _reportHistoryStore.LoadAsync();
            DispatchUi(() =>
            {
                Guid? selectedId = SelectedReport?.Id;
                ReportHistory.Clear();
                foreach (var record in records) ReportHistory.Add(record);
                SelectedReport = ReportHistory.FirstOrDefault(r => r.Id == selectedId) ?? ReportHistory.FirstOrDefault();
                ReportHistoryStatus = records.Count == 0
                    ? "Bu kullanıcı için henüz kaydedilmiş tarama yok. Yeni tamamlanan, iptal edilen veya başarısız taramalar burada görünür."
                    : $"{records.Count} kayıt. Bu cihazda bu uygulamanın gözlemlediği taramalar; servis geçmişinin tamamı değildir.";
            });
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "Could not load per-user scan report history");
            DispatchUi(() => ReportHistoryStatus = "Rapor geçmişi okunamadı: " + ex.Message);
        }
    }

    private async Task PersistReportAsync(ScanReportRecord record)
    {
        try
        {
            await _reportHistoryStore.AppendAsync(record);
            await RefreshReportsAsync();
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "Could not persist final scan report {ReportId}", record.Id);
            DispatchUi(() => ReportHistoryStatus = "Tarama sonucu yalnız bu oturumda mevcut; geçmiş kaydı başarısız: " + ex.Message);
        }
    }

    /// <summary>Exports the selected persisted report, including its actual status and coverage limits.</summary>
    [RelayCommand]
    public Task ExportSelectedReportAsync() => ExportReportAsync(SelectedReport);

    /// <summary>Exports the most recent observed final scan; opening the scanner alone never synthesizes a report.</summary>
    [RelayCommand]
    public Task ExportScanReportAsync() => ExportReportAsync(_lastReport);

    private async Task ExportReportAsync(ScanReportRecord? report)
    {
        if (report == null)
        {
            ReportHistoryStatus = "Dışa aktarılacak gerçek tarama sonucu seçilmedi.";
            _toastService?.ShowToast("Rapor yok", ReportHistoryStatus, "Warning");
            return;
        }
        if (Application.Current == null) return;
        string path = string.Empty;
        try
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Tarama Raporunu Dışa Aktar",
                InitialDirectory = ScanReportGenerator.GetSuggestedInitialDirectory(),
                FileName = ScanReportGenerator.GetDefaultReportFileName(report.Result.StartedAt.ToLocalTime()),
                Filter = "Metin Raporu (*.txt)|*.txt|JSON Raporu (*.json)|*.json",
                DefaultExt = ".txt",
                RestoreDirectory = true
            };
            Window? owner = Application.Current.Windows.OfType<Views.ActiveScanWindow>().FirstOrDefault(w => w.IsVisible) ?? Application.Current.MainWindow;
            if ((owner == null ? dialog.ShowDialog() : dialog.ShowDialog(owner)) != true) return;
            path = dialog.FileName;
            string content = path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                ? ScanReportGenerator.GenerateJsonReport(report)
                : ScanReportGenerator.GenerateTextReport(report.Result.StartedAt.ToLocalTime(), FormatDuration(TimeSpan.FromMilliseconds(report.Result.ElapsedMs)),
                    report.Result.ScanType.ToString(), report.Result.ScannedFiles, report.Result.Findings, report.Actions,
                    report.Result.SkippedFiles, report.Result.FailedFiles, report.Result.TimedOutFiles, report.ResourceProfile, report.Result.Status, report.Result.Coverage, report.Result.FailureInfo);
            await File.WriteAllTextAsync(path, content, System.Text.Encoding.UTF8);
            _toastService?.ShowToast("Rapor Kaydedildi", Path.GetFileName(path), "Success");
            ReportHistoryStatus = "Rapor kaydedildi: " + path;
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "Could not export scan report to {Path}", path);
            ReportHistoryStatus = "Rapor kaydedilemedi: " + ex.Message;
            _toastService?.ShowToast("Rapor Hatası", ReportHistoryStatus, "Danger");
        }
    }

    private static void DispatchUi(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess()) action();
        else dispatcher.Invoke(action);
    }

    private void RecordConfirmedAction(AegisPC.Core.Models.SecurityFinding finding, string label)
    {
        _confirmedActions[finding.ObjectPath] = label;
        if (_lastReport != null)
        {
            _lastReport.Actions[finding.ObjectPath] = label;
            if (_persistReportHistory) _ = PersistReportAsync(_lastReport);
        }
    }
        /// <summary>Formats observed elapsed time, clamping invalid negative durations to zero.</summary>
        public static string FormatDuration(TimeSpan elapsed)
        {
            if (elapsed < TimeSpan.Zero)
            {
                elapsed = TimeSpan.Zero;
            }

            if (elapsed.TotalHours >= 1)
            {
                return $"{(int)elapsed.TotalHours} sa {elapsed.Minutes:D2} dk {elapsed.Seconds:D2} sn";
            }
            return $"{elapsed.Minutes} dk {elapsed.Seconds:D2} sn";
        }

        /// <summary>Formats an engine-supplied remaining-time estimate, explicitly retaining unknown estimates.</summary>
        public static string FormatEta(double? remainingSeconds, int scanned, int total)
        {
            string counts = total > 0 ? $"({scanned:N0} / {total:N0} dosya)" : $"({scanned:N0} dosya)";
            if (!remainingSeconds.HasValue || !double.IsFinite(remainingSeconds.Value) || remainingSeconds.Value <= 0 || remainingSeconds.Value > TimeSpan.MaxValue.TotalSeconds)
            {
                return $"Kalan: tahmin ediliyor {counts}";
            }

            var ts = TimeSpan.FromSeconds(remainingSeconds.Value);
            if (ts.TotalHours >= 1)
            {
                return $"Kalan: ~{(int)ts.TotalHours} sa {ts.Minutes} dk {ts.Seconds} sn {counts}";
            }
            if (ts.TotalMinutes >= 1)
            {
                return $"Kalan: ~{ts.Minutes} dk {ts.Seconds} sn {counts}";
            }
            return $"Kalan: ~{ts.Seconds} sn {counts}";
        }
}
