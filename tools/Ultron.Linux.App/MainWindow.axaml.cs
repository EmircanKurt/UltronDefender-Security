using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Ultron.PortableInspection;

namespace Ultron.Linux.App;

/// <summary>Provides the actual desktop pickers, manual scan controls and explicit JSON export workflow.</summary>
public sealed partial class MainWindow : Window
{
    private readonly ScanPresentation _state = new();
    private readonly List<InspectionReport> _reports = [];
    private CancellationTokenSource? _cancellation;
    private ScanControl? _control;
    private string _reportScope = string.Empty;
    private string _outcome = "NotStarted";

    /// <summary>Creates the graphical shell with no selected path and no background scan.</summary>
    public MainWindow()
    {
        AvaloniaXamlLoader.Load(this);
        DataContext = _state;
        Closing += (_, _) => _cancellation?.Cancel();
    }

    private async void ChooseFile(object? sender, RoutedEventArgs args)
    {
        if (_state.IsScanning) return;
        try
        {
            var files = await StorageProvider.OpenFilePickerAsync(new() { Title = "İncelenecek dosyayı seçin", AllowMultiple = false });
            if (files.Count > 0) SelectPath(files[0].TryGetLocalPath());
        }
        catch (Exception ex) { ShowFailure("File picker", ex); }
    }

    private async void ChooseFolder(object? sender, RoutedEventArgs args)
    {
        if (_state.IsScanning) return;
        try
        {
            var folders = await StorageProvider.OpenFolderPickerAsync(new() { Title = "İncelenecek klasörü seçin", AllowMultiple = false });
            if (folders.Count > 0) SelectPath(folders[0].TryGetLocalPath());
        }
        catch (Exception ex) { ShowFailure("Folder picker", ex); }
    }

    private void SelectPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) { _state.Status = "Yerel dosya sistemi yolu alınamadı."; return; }
        _state.SelectedPath = path;
        _state.Status = "Kapsam seçildi; başlatmanız bekleniyor.";
    }

    private async void StartScan(object? sender, RoutedEventArgs args)
    {
        if (!_state.CanStart) return;
        _state.Reset(); _reports.Clear(); _state.IsScanning = true; _state.IsPaused = false;
        _state.Status = "Salt okunur inceleme sürüyor…";
        _reportScope = _state.SelectedPath; _outcome = "Running";
        _cancellation = new(); _control = new();
        try
        {
            string selectedPath = _state.SelectedPath;
            var progress = new UiProgress(report => { _reports.Add(report); _state.Add(report); });
            await Task.Run(async () =>
            {
                var rules = DefaultManagedRules.Create();
                var scanner = new ManualScopeScanner(new PreviewInspector(rules));
                await scanner.ScanAsync(selectedPath, _control, progress, _cancellation.Token);
            });
            _outcome = "CompletedWithReportedCoverage";
            _state.Status = "İnceleme bitti; kapsam eksikleri sonuçlarda gösterilir.";
        }
        catch (OperationCanceledException) { _outcome = "CancelledIncomplete"; _state.Status = "Tarama iptal edildi; kalan kapsam incelenmedi."; }
        catch (Exception ex) { _outcome = "FailedIncomplete"; ShowFailure("Manual scan", ex); }
        finally
        {
            // Flush queued completed reports before enabling export.
            await Dispatcher.UIThread.InvokeAsync(() => { }, DispatcherPriority.Background);
            _state.IsScanning = false; _state.IsPaused = false;
            _cancellation.Dispose(); _cancellation = null; _control = null;
        }
    }

    private void TogglePause(object? sender, RoutedEventArgs args)
    {
        if (_control == null) return;
        if (_control.IsPaused) { _control.Resume(); _state.IsPaused = false; _state.Status = "Salt okunur inceleme sürüyor…"; }
        else { _control.Pause(); _state.IsPaused = true; _state.Status = "Duraklatıldı; mevcut sınırlı işlem tamamlanabilir."; }
    }

    private void CancelScan(object? sender, RoutedEventArgs args) => _cancellation?.Cancel();

    private async void ExportJson(object? sender, RoutedEventArgs args)
    {
        if (!_state.CanExport) return;
        try
        {
            var snapshot = InspectionExportSnapshot.Capture(_reportScope, _outcome, _reports);
            var destination = await StorageProvider.SaveFilePickerAsync(new()
            {
                Title = "İnceleme raporunu kaydet", SuggestedFileName = "ultron-linux-preview.json",
                FileTypeChoices = [new("JSON") { Patterns = ["*.json"] }]
            });
            if (destination == null) return;
            await using var output = await destination.OpenWriteAsync();
            await snapshot.WriteAsync(output);
            _state.Status = "JSON raporu seçtiğiniz konuma kaydedildi.";
        }
        catch (Exception ex) { ShowFailure("JSON export", ex); }
    }

    private void ShowFailure(string operation, Exception exception)
    {
        Trace.TraceError("{0} failed: {1}", operation, exception);
        _state.Status = "İşlem tamamlanamadı: " + exception.Message;
    }

    private sealed class UiProgress(Action<InspectionReport> report) : IProgress<InspectionReport>
    {
        public void Report(InspectionReport value) => Dispatcher.UIThread.Post(() => report(value));
    }
}
