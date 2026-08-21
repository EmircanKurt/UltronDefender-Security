using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.BrowserSecurity.Applications;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class ApplicationsViewModel : ObservableObject
    {
        private List<InstalledApplication> _allApps = new();

        [ObservableProperty]
        private string pageTitle = "Yüklü Uygulamalar Envanteri";

        [ObservableProperty]
        private ObservableCollection<InstalledApplication> applications = new();

        [ObservableProperty]
        private InstalledApplication? selectedApp;

        [ObservableProperty]
        private string searchText = string.Empty;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        public ApplicationsViewModel()
        {
            _ = LoadApplicationsAsync();
        }

        partial void OnSearchTextChanged(string value) => FilterApps();

        private void FilterApps()
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                Applications = new ObservableCollection<InstalledApplication>(_allApps);
            }
            else
            {
                var filtered = _allApps.Where(a =>
                    a.DisplayName.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    (a.Publisher != null && a.Publisher.Contains(SearchText, StringComparison.OrdinalIgnoreCase)));
                Applications = new ObservableCollection<InstalledApplication>(filtered);
            }
        }

        [RelayCommand]
        public async Task LoadApplicationsAsync()
        {
            IsLoading = true;
            StatusMessage = "Kayıt defteri ve yüklü programlar taranıyor...";
            try
            {
                _allApps = await Task.Run(() => ApplicationInventoryScanner.ScanInstalledApplications());
                FilterApps();
                StatusMessage = $"Toplam {_allApps.Count} yüklü uygulama listelendi.";
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
        public void UninstallApplication(InstalledApplication? app)
        {
            var target = app ?? SelectedApp;
            if (target == null || string.IsNullOrWhiteSpace(target.UninstallString)) return;

            try
            {
                var uninstaller = target.UninstallString.Trim();
                string fileName;
                string arguments = string.Empty;

                if (uninstaller.StartsWith("\""))
                {
                    var endQuote = uninstaller.IndexOf('"', 1);
                    if (endQuote > 0)
                    {
                        fileName = uninstaller.Substring(1, endQuote - 1);
                        arguments = uninstaller.Length > endQuote + 1 ? uninstaller.Substring(endQuote + 1).Trim() : string.Empty;
                    }
                    else
                    {
                        fileName = uninstaller;
                    }
                }
                else
                {
                    var parts = uninstaller.Split(' ', 2);
                    fileName = parts[0];
                    if (parts.Length > 1) arguments = parts[1];
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = true
                });

                StatusMessage = $"'{target.DisplayName}' kaldırma programı başlatıldı.";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Kaldırıcı başlatılamadı: {ex.Message}";
            }
        }
    }
}
