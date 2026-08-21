using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class WindowsEventsViewModel : ObservableObject
    {
        private readonly IWindowsEventAnalyzer? _eventAnalyzer;
        private List<WindowsEventEntry> _allEvents = new();

        [ObservableProperty]
        private string pageTitle = "Windows Olay Günlüğü Analizi";

        [ObservableProperty]
        private ObservableCollection<WindowsEventEntry> events = new();

        [ObservableProperty]
        private WindowsEventEntry? selectedEvent;

        [ObservableProperty]
        private string searchText = string.Empty;

        [ObservableProperty]
        private string selectedChannel = "Tümü";

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        public List<string> Channels { get; } = new() { "Tümü", "Application", "System" };

        public WindowsEventsViewModel(IWindowsEventAnalyzer? eventAnalyzer = null)
        {
            _eventAnalyzer = eventAnalyzer;
            _ = LoadEventsAsync();
        }

        partial void OnSearchTextChanged(string value) => FilterEvents();
        partial void OnSelectedChannelChanged(string value) => FilterEvents();

        private void FilterEvents()
        {
            var query = _allEvents.AsEnumerable();

            if (!string.IsNullOrEmpty(SelectedChannel) && SelectedChannel != "Tümü")
            {
                query = query.Where(e => e.LogName.Equals(SelectedChannel, StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrWhiteSpace(SearchText))
            {
                query = query.Where(e =>
                    e.ProviderName.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    e.EventId.ToString().Contains(SearchText) ||
                    e.Message.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
            }

            Events = new ObservableCollection<WindowsEventEntry>(query);
        }

        [RelayCommand]
        public async Task LoadEventsAsync()
        {
            if (_eventAnalyzer == null) return;

            IsLoading = true;
            StatusMessage = "Windows olay günlükleri taranıyor...";
            try
            {
                _allEvents = await _eventAnalyzer.GetRecentEventsAsync(TimeSpan.FromHours(24));
                FilterEvents();
                StatusMessage = $"Son 24 saat içinde {_allEvents.Count} önemli olay kaydedildi.";
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
