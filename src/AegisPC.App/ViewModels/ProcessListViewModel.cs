using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Performance.Process;
using AegisPC.Security.Safety;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;

namespace AegisPC.App.ViewModels;

/// <summary>Lists process snapshots and routes explicit user actions through creation-time and path validation.</summary>
public partial class ProcessListViewModel : ObservableObject
{
    private readonly IProcessMonitor? _processMonitor;
    private readonly ProcessTerminationService? _terminationService;
    private readonly ISettingsService? _settingsService;
    private readonly ILogger<ProcessListViewModel>? _logger;
    private readonly SemaphoreSlim _loadGate = new(1, 1);
    private int _terminationGate;
    private List<ProcessInfo> _allProcesses = new();

    [ObservableProperty] private string pageTitle = "Süreçler";
    [ObservableProperty] private ObservableCollection<ProcessInfo> processes = new();
    [ObservableProperty] private ProcessInfo? selectedProcess;
    [ObservableProperty] private string searchText = string.Empty;
    [ObservableProperty] private bool hideWindowsServices = true;
    [ObservableProperty] private int sortMode;
    [ObservableProperty] private bool isGpuSupported = true;
    [ObservableProperty] private bool isLoading;
    [ObservableProperty] private string statusMessage = string.Empty;

    /// <summary>Creates the process page with optional dependencies; failures remain visible to the user.</summary>
    public ProcessListViewModel(IProcessMonitor? processMonitor = null, ProcessTerminationService? terminationService = null,
        ISettingsService? settingsService = null, ILogger<ProcessListViewModel>? logger = null)
    {
        _processMonitor = processMonitor;
        _terminationService = terminationService;
        _settingsService = settingsService;
        _logger = logger;
        try { isGpuSupported = _processMonitor?.IsGpuSupported ?? ProcessMonitorService.IsGpuEngineAvailable(); }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to read GPU monitoring capability");
            System.Diagnostics.Trace.TraceWarning("Failed to read GPU capability: {0}", ex.Message);
            isGpuSupported = false;
        }
        hideWindowsServices = _settingsService?.GetSetting<bool>("ProcessManager_HideWindowsServices", true) ?? true;
        _ = LoadProcessesAsync();
    }

    /// <summary>Changes display sorting only, never a security decision.</summary>
    [RelayCommand]
    public void SetSortMode(object? parameter)
    {
        if (parameter != null && int.TryParse(parameter.ToString(), out int mode))
        {
            SortMode = mode;
            FilterProcesses();
        }
    }

    partial void OnSearchTextChanged(string value) => FilterProcesses();
    partial void OnHideWindowsServicesChanged(bool value)
    {
        try
        {
            _settingsService?.SetSetting("ProcessManager_HideWindowsServices", value);
            _ = SaveDisplayPreferenceAsync();
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to update process display preference");
            StatusMessage = $"Görüntüleme tercihi kaydedilemedi: {ex.Message}";
        }
        FilterProcesses();
    }

    /// <summary>
    /// Applies a display-only service-session or verified OS-publisher filter.
    /// Names alone never hide a process and this filter never establishes a clean verdict.
    /// </summary>
    public static bool IsWindowsServiceOrSystem(ProcessInfo p)
    {
        if (p == null) return false;
        if (p.PID is 0 or 4 || p.SessionId == 0) return true;
        if (!p.IsSigned || !TrustedSoftwarePolicy.IsTrustedOsPublisher(p.SignaturePublisher ?? p.Publisher)) return false;
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(winDir) || string.IsNullOrWhiteSpace(p.ExecutablePath)) return false;
        try
        {
            string path = Path.GetFullPath(p.ExecutablePath);
            return path.StartsWith(Path.Combine(winDir, "System32") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith(Path.Combine(winDir, "SysWOW64") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            System.Diagnostics.Trace.TraceWarning("Invalid process display path: {0}", ex.Message);
            return false;
        }
    }

    private void FilterProcesses()
    {
        var query = _allProcesses.AsEnumerable();
        if (HideWindowsServices) query = query.Where(p => !IsWindowsServiceOrSystem(p));
        if (!string.IsNullOrWhiteSpace(SearchText))
            query = query.Where(p => p.Name.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                p.PID.ToString().Contains(SearchText) || p.ExecutablePath.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
        query = SortMode switch
        {
            0 => query.OrderByDescending(p => p.MemoryBytes).ThenByDescending(p => p.CpuPercent),
            1 => query.OrderByDescending(p => p.CpuPercent).ThenByDescending(p => p.MemoryBytes),
            2 => query.OrderByDescending(p => p.GpuPercent).ThenByDescending(p => p.MemoryBytes),
            _ => query.OrderByDescending(p => p.MemoryBytes)
        };
        var selected = SelectedProcess;
        Processes = new ObservableCollection<ProcessInfo>(query.ToList());
        if (selected != null)
            SelectedProcess = Processes.FirstOrDefault(p => p.PID == selected.PID && p.StartTime == selected.StartTime);
    }

    /// <summary>Serializes refreshes and awaits dispatcher publication, including dispatcher-free test or headless contexts.</summary>
    [RelayCommand]
    public async Task LoadProcessesAsync()
    {
        if (_processMonitor == null) { StatusMessage = "Süreç izleme servisi kullanılamıyor."; return; }
        if (!await _loadGate.WaitAsync(0)) return;
        try
        {
            await RunOnUiAsync(() => { IsLoading = true; StatusMessage = "Süreçler listeleniyor..."; });
            await _processMonitor.RefreshAsync();
            var procs = await _processMonitor.GetAllProcessesAsync();
            await RunOnUiAsync(() =>
            {
                _allProcesses = procs;
                FilterProcesses();
                StatusMessage = $"Toplam {_allProcesses.Count} aktif süreç listelendi.";
            });
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to refresh process snapshots");
            await RunOnUiAsync(() => StatusMessage = $"Süreç listesi yüklenemedi: {ex.Message}");
        }
        finally
        {
            await RunOnUiAsync(() => IsLoading = false);
            _loadGate.Release();
        }
    }

    /// <summary>Requests termination only after selected executable and start-time identity are verified.</summary>
    [RelayCommand]
    public Task TerminateProcessAsync(ProcessInfo? process) => TerminateSelectedAsync(process ?? SelectedProcess, false);

    /// <summary>Requests best-effort tree termination after root identity validation; does not claim every descendant exited.</summary>
    [RelayCommand]
    public Task TerminateTreeAsync(ProcessInfo? process) => TerminateSelectedAsync(process ?? SelectedProcess, true);

    private async Task TerminateSelectedAsync(ProcessInfo? target, bool killTree)
    {
        if (target == null) { StatusMessage = "Önce bir süreç seçin."; return; }
        if (_terminationService == null) { StatusMessage = "Süreç sonlandırma servisi kullanılamıyor."; return; }
        if (Interlocked.CompareExchange(ref _terminationGate, 1, 0) != 0) return;
        try
        {
            StatusMessage = $"'{target.Name}' (PID: {target.PID}) kimliği doğrulanıyor...";
            var result = await _terminationService.TerminateSelectedProcessAsync(target, killTree);
            if (result.Success) await LoadProcessesAsync();
            // A refresh count must not conceal access denial or a partial tree outcome.
            StatusMessage = result.Message;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "User-requested process action failed for PID {Pid}", target.PID);
            StatusMessage = $"Süreç işlemi tamamlanamadı: {ex.Message}";
        }
        finally { Interlocked.Exchange(ref _terminationGate, 0); }
    }

    private async Task SaveDisplayPreferenceAsync()
    {
        if (_settingsService == null) return;
        try { await _settingsService.SaveAsync(); }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to persist process display preference");
            await RunOnUiAsync(() => StatusMessage = $"Görüntüleme tercihi kaydedilemedi: {ex.Message}");
        }
    }

    private static Task RunOnUiAsync(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher != null && !dispatcher.CheckAccess()) return dispatcher.InvokeAsync(action).Task;
        action();
        return Task.CompletedTask;
    }
}
