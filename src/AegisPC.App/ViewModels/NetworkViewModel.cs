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
    public partial class NetworkViewModel : ObservableObject
    {
        private readonly INetworkMonitor? _networkMonitor;
        private List<NetworkConnection> _allConnections = new();

        [ObservableProperty]
        private string pageTitle = "Ağ Güvenliği ve Bağlantılar";

        [ObservableProperty]
        private ObservableCollection<NetworkConnection> connections = new();

        [ObservableProperty]
        private string searchText = string.Empty;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        public NetworkViewModel(INetworkMonitor? networkMonitor = null)
        {
            _networkMonitor = networkMonitor;
            _ = LoadConnectionsAsync();
        }

        partial void OnSearchTextChanged(string value)
        {
            FilterConnections();
        }

        private void FilterConnections()
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                Connections = new ObservableCollection<NetworkConnection>(_allConnections);
            }
            else
            {
                var filtered = _allConnections.Where(c =>
                    c.ProcessName.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    c.PID.ToString().Contains(SearchText) ||
                    c.LocalAddress.Contains(SearchText) ||
                    c.RemoteAddress.Contains(SearchText) ||
                    c.State.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
                Connections = new ObservableCollection<NetworkConnection>(filtered);
            }
        }

        [RelayCommand]
        public async Task LoadConnectionsAsync()
        {
            if (_networkMonitor == null) return;

            IsLoading = true;
            StatusMessage = "Ağ bağlantıları taranıyor...";
            try
            {
                _allConnections = await _networkMonitor.GetActiveConnectionsAsync();
                FilterConnections();
                StatusMessage = $"Toplam {_allConnections.Count} aktif TCP bağlantısı listelendi.";
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
