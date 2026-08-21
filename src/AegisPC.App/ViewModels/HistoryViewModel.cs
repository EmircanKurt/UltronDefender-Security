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
    public partial class HistoryViewModel : ObservableObject
    {
        private readonly IAuditLogService? _auditLogService;
        private List<AuditLogEntry> _allLogs = new();

        [ObservableProperty]
        private string pageTitle = "İşlem ve Güvenlik Geçmişi (Audit Logs)";

        [ObservableProperty]
        private ObservableCollection<AuditLogEntry> logs = new();

        [ObservableProperty]
        private string searchText = string.Empty;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        [ObservableProperty]
        private bool hasNoLogs = true;

        public HistoryViewModel(IAuditLogService? auditLogService = null)
        {
            _auditLogService = auditLogService;
            _ = LoadLogsAsync();
        }

        partial void OnSearchTextChanged(string value) => FilterLogs();

        private void FilterLogs()
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                Logs = new ObservableCollection<AuditLogEntry>(_allLogs);
            }
            else
            {
                var filtered = _allLogs.Where(l =>
                    l.TargetName.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    l.Action.ToString().Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    (l.Details != null && l.Details.Contains(SearchText, StringComparison.OrdinalIgnoreCase)));
                Logs = new ObservableCollection<AuditLogEntry>(filtered);
            }
        }

        [RelayCommand]
        public async Task LoadLogsAsync()
        {
            if (_auditLogService == null) return;

            IsLoading = true;
            StatusMessage = "İşlem geçmişi yükleniyor...";
            try
            {
                _allLogs = await _auditLogService.GetLogsAsync();
                FilterLogs();
                HasNoLogs = _allLogs.Count == 0;
                StatusMessage = $"Toplam {_allLogs.Count} işlem günlüğü kaydedildi.";
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
