using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Ultron.PortableInspection;

namespace Ultron.Linux.App;

/// <summary>Owns presentation state only; default construction neither selects a scope nor starts a scan.</summary>
public sealed class ScanPresentation : INotifyPropertyChanged
{
    private string _selectedPath = string.Empty;
    private bool _isScanning;
    private bool _isPaused;
    private string _status = "Tarama hazır";
    private string _activePath = string.Empty;
    private int _count;

    /// <summary>Notifies the GUI of user-visible state changes.</summary>
    public event PropertyChangedEventHandler? PropertyChanged;
    /// <summary>Returns bounded rows for presentation, independent of the full export report.</summary>
    public ObservableCollection<ResultRow> Rows { get; } = [];
    /// <summary>Returns the explicitly selected local path; selecting it never starts inspection.</summary>
    public string SelectedPath { get => _selectedPath; set { _selectedPath = value; Changed(); Changed(nameof(CanStart)); } }
    /// <summary>Reports an active manual task and enables pause/cancel controls.</summary>
    public bool IsScanning { get => _isScanning; set { _isScanning = value; Changed(); Changed(nameof(CanStart)); Changed(nameof(CanExport)); } }
    /// <summary>Reports admission pause state; existing bounded work can still finish.</summary>
    public bool IsPaused { get => _isPaused; set { _isPaused = value; Changed(); Changed(nameof(PauseLabel)); } }
    /// <summary>Returns whether manual initiation is available.</summary>
    public bool CanStart => !IsScanning && !string.IsNullOrWhiteSpace(SelectedPath);
    /// <summary>Returns whether a completed result collection can be exported.</summary>
    public bool CanExport => !IsScanning && _count > 0;
    /// <summary>Returns a Turkish label for pause or resume.</summary>
    public string PauseLabel => IsPaused ? "Devam et" : "Duraklat";
    /// <summary>Returns truthful task status, including failures and cancellation.</summary>
    public string Status { get => _status; set { _status = value; Changed(); } }
    /// <summary>Returns the last completed path; no personal paths are sent to a service.</summary>
    public string ActivePath { get => _activePath; set { _activePath = value; Changed(); } }
    /// <summary>Returns inspected report count without inventing a percentage before discovery finishes.</summary>
    public string ProgressText => $"{_count} dosya / kapsam raporu";
    /// <summary>Explains the row cap and the independent preview limitation.</summary>
    public string ResultsSummary => _count == 0 ? "Henüz tarama yapılmadı." : $"{_count} rapor. İlk 500 satır gösterilir; JSON tüm raporları içerir. Sonuçlar inceleme içindir, güvenli dosya onayı değildir.";

    /// <summary>Clears only in-memory report presentation for a newly requested scan.</summary>
    public void Reset()
    {
        Rows.Clear(); _count = 0; ActivePath = string.Empty;
        Changed(nameof(ProgressText)); Changed(nameof(ResultsSummary)); Changed(nameof(CanExport));
    }

    /// <summary>Adds a completed report on the UI thread while keeping rendering bounded.</summary>
    public void Add(InspectionReport report)
    {
        _count++;
        if (Rows.Count < 500) Rows.Add(new(report));
        ActivePath = report.Path;
        Changed(nameof(ProgressText)); Changed(nameof(ResultsSummary)); Changed(nameof(CanExport));
    }

    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
}

/// <summary>Formats a report as conservative human-readable Turkish GUI text.</summary>
public sealed class ResultRow(InspectionReport report)
{
    /// <summary>Returns the selected file or archive identifier as inert display text.</summary>
    public string Path => report.Path;
    /// <summary>Returns review, incomplete or unmatched-preview status; never claims a clean file.</summary>
    public string DisplayStatus => report.ReviewIndicators.Length > 0 ? "İnceleme gerekli" : report.ChecksComplete ? "Önizleme göstergesi bulunmadı" : "Bilinmiyor / eksik inceleme";
    /// <summary>Explains format, rule indicators, omissions and nested report count.</summary>
    public string Detail => string.Join(" · ", report.Formats.Concat(report.ReviewIndicators).Concat(report.Limitations)) +
        (report.Members.Length > 0 ? $" · {report.Members.Length} ZIP üyesi" : string.Empty);
}
