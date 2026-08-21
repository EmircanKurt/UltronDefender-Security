using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.Contracts.Services;
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
        private List<ProcessInfo> _allProcesses = new();

        [ObservableProperty]
        private string pageTitle = "Süreçler";

        [ObservableProperty]
        private ObservableCollection<ProcessInfo> processes = new();

        [ObservableProperty]
        private ProcessInfo? selectedProcess;

        [ObservableProperty]
        private string searchText = string.Empty;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        public ProcessListViewModel(IProcessMonitor? processMonitor = null, ProcessTerminationService? terminationService = null)
        {
            _processMonitor = processMonitor;
            _terminationService = terminationService;

            // Arka planda donma yapmadan yükle
            Task.Run(async () => await LoadProcessesAsync());
        }

        partial void OnSearchTextChanged(string value)
        {
            FilterProcesses();
        }

        private void FilterProcesses()
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                Processes = new ObservableCollection<ProcessInfo>(_allProcesses);
            }
            else
            {
                var filtered = _allProcesses.Where(p =>
                    p.Name.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    p.PID.ToString().Contains(SearchText) ||
                    p.ExecutablePath.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
                Processes = new ObservableCollection<ProcessInfo>(filtered);
            }
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
