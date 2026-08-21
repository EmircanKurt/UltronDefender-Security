using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class CrashAnalysisViewModel : ObservableObject
    {
        private readonly ICrashAnalyzer? _crashAnalyzer;

        [ObservableProperty]
        private string pageTitle = "Windows Çökme ve Donma Analizi";

        [ObservableProperty]
        private ObservableCollection<CrashEvent> crashes = new();

        [ObservableProperty]
        private CrashEvent? selectedCrash;

        [ObservableProperty]
        private CrashReport? selectedCrashReport;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        [ObservableProperty]
        private bool hasNoCrashes = true;

        public CrashAnalysisViewModel(ICrashAnalyzer? crashAnalyzer = null)
        {
            _crashAnalyzer = crashAnalyzer;
            _ = LoadCrashesAsync();
        }

        partial void OnSelectedCrashChanged(CrashEvent? value)
        {
            if (value != null && _crashAnalyzer != null)
            {
                _ = LoadCrashReportAsync(value);
            }
            else
            {
                SelectedCrashReport = null;
            }
        }

        private async Task LoadCrashReportAsync(CrashEvent crashEvent)
        {
            if (_crashAnalyzer == null) return;
            try
            {
                SelectedCrashReport = await _crashAnalyzer.BuildCrashReportAsync(crashEvent);
            }
            catch (Exception ex)
            {
                StatusMessage = $"Rapor oluşturulamadı: {ex.Message}";
            }
        }

        [RelayCommand]
        public async Task LoadCrashesAsync()
        {
            if (_crashAnalyzer == null) return;

            IsLoading = true;
            StatusMessage = "Sistem çökme ve donma günlükleri taranıyor...";
            try
            {
                var list = await _crashAnalyzer.GetRecentCrashesAsync(TimeSpan.FromDays(7));
                Crashes = new ObservableCollection<CrashEvent>(list);
                HasNoCrashes = Crashes.Count == 0;
                StatusMessage = $"Son 7 günde {Crashes.Count} çökme/donma olayı teşhis edildi.";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Hata: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
        }
    }
}
