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
        private bool hasNoExtensions;

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
                HasNoExtensions = Extensions.Count == 0;
                SelectedExtension = Extensions.FirstOrDefault();
            }
            else
            {
                Extensions.Clear();
                HasNoExtensions = true;
                SelectedExtension = null;
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

                // Eklentisi olan tarayıcı profillerini başa al ve eklenti sayısına göre sırala
                var orderedProfiles = _allProfiles
                    .OrderByDescending(p => p.Extensions.Count > 0)
                    .ThenByDescending(p => p.Extensions.Count)
                    .ThenBy(p => p.BrowserType.ToString())
                    .ThenBy(p => p.ProfileName)
                    .ToList();

                Profiles = new ObservableCollection<BrowserProfile>(orderedProfiles);

                // Otomatik seçim mantığı: Eklentisi olan tarayıcıyı seç; hiç yoksa ilk profili seç
                SelectedProfile = Profiles.FirstOrDefault(p => p.Extensions.Count > 0) ?? Profiles.FirstOrDefault();

                int totalExt = _allProfiles.Sum(p => p.Extensions.Count);
                int suspiciousExt = _allProfiles.Sum(p => p.Extensions.Count(e => e.RiskLevel >= Core.Enums.RiskLevel.Suspicious));

                if (SelectedProfile != null && SelectedProfile.Extensions.Count > 0)
                {
                    StatusMessage = $"{SelectedProfile.BrowserType} ({SelectedProfile.ProfileName}) tarayıcısında {SelectedProfile.Extensions.Count} eklenti bulundu ve otomatik seçildi. (Toplam: {_allProfiles.Count} profil, {totalExt} eklenti, {suspiciousExt} şüpheli).";
                }
                else
                {
                    StatusMessage = $"Toplam {_allProfiles.Count} profil ve {totalExt} eklenti bulundu ({suspiciousExt} şüpheli/yüksek yetkili).";
                }
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
