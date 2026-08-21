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
    public partial class BrowserSecurityViewModel : ObservableObject
    {
        private readonly IBrowserSecurityScanner? _browserScanner;
        private List<BrowserProfile> _allProfiles = new();

        [ObservableProperty]
        private string pageTitle = "Tarayıcı Güvenliği ve Eklenti Denetimi";

        [ObservableProperty]
        private ObservableCollection<BrowserProfile> profiles = new();

        [ObservableProperty]
        private BrowserProfile? selectedProfile;

        [ObservableProperty]
        private ObservableCollection<BrowserExtension> extensions = new();

        [ObservableProperty]
        private BrowserExtension? selectedExtension;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        public BrowserSecurityViewModel(IBrowserSecurityScanner? browserScanner = null)
        {
            _browserScanner = browserScanner;
            _ = LoadBrowserDataAsync();
        }

        partial void OnSelectedProfileChanged(BrowserProfile? value)
        {
            if (value != null)
            {
                Extensions = new ObservableCollection<BrowserExtension>(value.Extensions);
            }
            else
            {
                Extensions.Clear();
            }
        }

        [RelayCommand]
        public async Task LoadBrowserDataAsync()
        {
            if (_browserScanner == null) return;

            IsLoading = true;
            StatusMessage = "Yüklü tarayıcılar ve eklentiler taranıyor...";
            try
            {
                _allProfiles = await _browserScanner.ScanAllBrowsersAsync();
                Profiles = new ObservableCollection<BrowserProfile>(_allProfiles);

                if (Profiles.Count > 0)
                {
                    SelectedProfile = Profiles[0];
                }

                int totalExt = _allProfiles.Sum(p => p.Extensions.Count);
                int suspiciousExt = _allProfiles.Sum(p => p.Extensions.Count(e => e.RiskLevel >= Core.Enums.RiskLevel.Suspicious));

                StatusMessage = $"Toplam {_allProfiles.Count} profil ve {totalExt} eklenti bulundu ({suspiciousExt} şüpheli/yüksek yetkili).";
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
