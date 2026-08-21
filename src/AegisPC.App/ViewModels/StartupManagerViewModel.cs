using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Persistence.Startup;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class StartupManagerViewModel : ObservableObject
    {
        private readonly IStartupAnalyzer? _startupAnalyzer;
        private readonly StartupManagementService? _managementService;
        private List<StartupItem> _allItems = new();

        [ObservableProperty]
        private string pageTitle = "Başlangıç Uygulamaları ve Kalıcılık Yönetimi";

        [ObservableProperty]
        private ObservableCollection<StartupItem> startupItems = new();

        [ObservableProperty]
        private StartupItem? selectedItem;

        [ObservableProperty]
        private string searchText = string.Empty;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        [ObservableProperty]
        private int totalCount;

        [ObservableProperty]
        private int suspiciousCount;

        public StartupManagerViewModel(IStartupAnalyzer? startupAnalyzer = null, StartupManagementService? managementService = null)
        {
            _startupAnalyzer = startupAnalyzer;
            _managementService = managementService;
            _ = LoadItemsAsync();
        }

        partial void OnSearchTextChanged(string value) => FilterItems();

        private void FilterItems()
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                StartupItems = new ObservableCollection<StartupItem>(_allItems);
            }
            else
            {
                var filtered = _allItems.Where(i =>
                    i.Name.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    i.FilePath.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    i.Source.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
                StartupItems = new ObservableCollection<StartupItem>(filtered);
            }
        }

        [RelayCommand]
        public async Task LoadItemsAsync()
        {
            if (_startupAnalyzer == null) return;

            IsLoading = true;
            StatusMessage = "Başlangıç girdileri ve kayıt defteri taranıyor...";
            try
            {
                _allItems = await _startupAnalyzer.GetStartupItemsAsync();
                TotalCount = _allItems.Count;
                SuspiciousCount = _allItems.Count(i => i.RiskLevel >= Core.Enums.RiskLevel.Suspicious);
                FilterItems();
                StatusMessage = $"Toplam {TotalCount} otomatik başlangıç noktası tespit edildi.";
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

        [RelayCommand]
        public async Task DisableItemAsync(StartupItem? item)
        {
            var target = item ?? SelectedItem;
            if (target == null || _managementService == null) return;

            StatusMessage = $"'{target.Name}' başlangıçtan devre dışı bırakılıyor...";
            bool success = await _managementService.DisableStartupItemAsync(target);

            if (success)
            {
                StatusMessage = $"'{target.Name}' başarıyla devre dışı bırakıldı.";
                await LoadItemsAsync();
            }
            else
            {
                StatusMessage = "Başlangıç girdisi devre dışı bırakılamadı. Yönetici izinleri gerekebilir.";
            }
        }

        [RelayCommand]
        public async Task ToggleItemStateAsync(StartupItem? item)
        {
            var target = item ?? SelectedItem;
            if (target == null || _managementService == null) return;

            if (target.IsEnabled)
            {
                await DisableItemAsync(target);
            }
            else
            {
                StatusMessage = $"'{target.Name}' başlangıçta etkinleştiriliyor...";
                bool success = await _managementService.EnableStartupItemAsync(target);
                if (success)
                {
                    StatusMessage = $"'{target.Name}' başarıyla etkinleştirildi.";
                    await LoadItemsAsync();
                }
                else
                {
                    StatusMessage = "Başlangıç girdisi etkinleştirilemedi.";
                }
            }
        }
    }
}
