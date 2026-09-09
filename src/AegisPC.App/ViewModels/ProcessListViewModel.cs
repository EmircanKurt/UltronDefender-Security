using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Models;
using AegisPC.Performance.Process;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class ProcessListViewModel : ObservableObject
    {
        private readonly IProcessMonitor? _processMonitor;
        private readonly ProcessTerminationService? _terminationService;
        private readonly ISettingsService? _settingsService;
        private List<ProcessInfo> _allProcesses = new();

        private static readonly HashSet<string> KnownWindowsServices = new(StringComparer.OrdinalIgnoreCase)
        {
            "System", "Idle", "Registry", "Memory Compression",
            "smss", "csrss", "wininit", "winlogon", "services", "lsass",
            "svchost", "fontdrvhost", "dwm", "spoolsv", "taskhostw", "sihost",
            "ctfmon", "SearchHost", "SearchIndexer", "SecurityHealthService",
            "SecurityHealthSystray", "MsMpEng", "NisSrv", "WmiPrvSE", "dllhost",
            "conhost", "RuntimeBroker", "ShellExperienceHost", "StartMenuExperienceHost",
            "smartscreen", "ApplicationFrameHost", "TextInputHost", "audiodg",
            "dasHost", "SystemSettings", "wlanext", "LocationNotificationWindows",
            "TrustedInstaller", "sppsvc", "tiworker", "compattelrunner"
        };

        [ObservableProperty]
        private string pageTitle = "Süreçler";

        [ObservableProperty]
        private ObservableCollection<ProcessInfo> processes = new();

        [ObservableProperty]
        private ProcessInfo? selectedProcess;

        [ObservableProperty]
        private string searchText = string.Empty;

        [ObservableProperty]
        private bool hideWindowsServices = true;

        [ObservableProperty]
        private int sortMode = 0; // 0 = En Çok RAM (varsayılan), 1 = En Çok CPU, 2 = GPU

        [ObservableProperty]
        private bool isGpuSupported = true;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        public ProcessListViewModel(
            IProcessMonitor? processMonitor = null,
            ProcessTerminationService? terminationService = null,
            ISettingsService? settingsService = null)
        {
            _processMonitor = processMonitor;
            _terminationService = terminationService;
            _settingsService = settingsService;

            try
            {
                isGpuSupported = _processMonitor?.IsGpuSupported ?? ProcessMonitorService.IsGpuEngineAvailable();
            }
            catch
            {
                isGpuSupported = false;
            }

            hideWindowsServices = _settingsService?.GetSetting<bool>("ProcessManager_HideWindowsServices", true) ?? true;

            // Arka planda donma yapmadan yükle
            Task.Run(async () => await LoadProcessesAsync());
        }

        [RelayCommand]
        public void SetSortMode(object? parameter)
        {
            if (parameter != null && int.TryParse(parameter.ToString(), out int mode))
            {
                SortMode = mode;
                FilterProcesses();
            }
        }

        partial void OnSearchTextChanged(string value)
        {
            FilterProcesses();
        }

        partial void OnHideWindowsServicesChanged(bool value)
        {
            try
            {
                _settingsService?.SetSetting("ProcessManager_HideWindowsServices", value);
                _ = _settingsService?.SaveAsync();
            }
            catch { }
            FilterProcesses();
        }

        public static bool IsWindowsServiceOrSystem(ProcessInfo p)
        {
            if (p == null) return false;

            // 1. Session 0: Windows mimarisinde tüm Windows servisleri Session 0'da izole çalışır
            if (p.SessionId == 0) return true;

            // 2. Kritik / Temel Windows süreçleri
            if (CriticalProcesses.IsCriticalProcess(p.Name)) return true;

            // 3. Bilinen Windows servis ve arka plan sistem süreçleri
            string cleanName = p.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? p.Name[..^4]
                : p.Name;

            if (KnownWindowsServices.Contains(p.Name) || KnownWindowsServices.Contains(cleanName))
            {
                return true;
            }

            // 4. Windows sistem dizinindeki Microsoft servis ikilileri
            if (!string.IsNullOrEmpty(p.ExecutablePath))
            {
                string path = p.ExecutablePath;
                string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (path.StartsWith(winDir, StringComparison.OrdinalIgnoreCase))
                {
                    if (path.Contains("\\System32\\", StringComparison.OrdinalIgnoreCase) ||
                        path.Contains("\\SysWOW64\\", StringComparison.OrdinalIgnoreCase))
                    {
                        if (p.Publisher != null && p.Publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private void FilterProcesses()
        {
            var query = _allProcesses.AsEnumerable();

            if (HideWindowsServices)
            {
                query = query.Where(p => !IsWindowsServiceOrSystem(p));
            }

            if (!string.IsNullOrWhiteSpace(SearchText))
            {
                query = query.Where(p =>
                    p.Name.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    p.PID.ToString().Contains(SearchText) ||
                    p.ExecutablePath.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
            }

            query = SortMode switch
            {
                0 => query.OrderByDescending(p => p.MemoryBytes).ThenByDescending(p => p.CpuPercent),
                1 => query.OrderByDescending(p => p.CpuPercent).ThenByDescending(p => p.MemoryBytes),
                2 => query.OrderByDescending(p => p.GpuPercent).ThenByDescending(p => p.MemoryBytes),
                _ => query.OrderByDescending(p => p.MemoryBytes)
            };

            Processes = new ObservableCollection<ProcessInfo>(query.ToList());
        }

        [RelayCommand]
        public async Task LoadProcessesAsync()
        {
            if (_processMonitor == null) return;

            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                IsLoading = true;
                StatusMessage = "Süreçler listeleniyor...";
            });

            try
            {
                await _processMonitor.RefreshAsync();
                var procs = await _processMonitor.GetAllProcessesAsync();

                Application.Current?.Dispatcher?.InvokeAsync(() =>
                {
                    _allProcesses = procs;
                    FilterProcesses();
                    StatusMessage = $"Toplam {_allProcesses.Count} aktif süreç listelendi.";
                });
            }
            catch (Exception ex)
            {
                Application.Current?.Dispatcher?.InvokeAsync(() =>
                {
                    StatusMessage = $"Hata: {ex.Message}";
                });
            }
            finally
            {
                Application.Current?.Dispatcher?.InvokeAsync(() => IsLoading = false);
            }
        }

        [RelayCommand]
        public async Task TerminateProcessAsync(ProcessInfo? process)
        {
            var target = process ?? SelectedProcess;
            if (target == null || _terminationService == null) return;

            StatusMessage = $"'{target.Name}' (PID: {target.PID}) sonlandırılıyor...";
            var result = await _terminationService.TerminateProcessAsync(target.PID, killTree: false);

            StatusMessage = result.Message;
            if (result.Success)
            {
                await LoadProcessesAsync();
            }
        }

        [RelayCommand]
        public async Task TerminateTreeAsync(ProcessInfo? process)
        {
            var target = process ?? SelectedProcess;
            if (target == null || _terminationService == null) return;

            StatusMessage = $"'{target.Name}' ve tüm alt süreçleri sonlandırılıyor...";
            var result = await _terminationService.TerminateProcessAsync(target.PID, killTree: true);

            StatusMessage = result.Message;
            if (result.Success)
            {
                await LoadProcessesAsync();
            }
        }
    }
}
