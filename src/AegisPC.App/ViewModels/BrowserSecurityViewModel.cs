using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.BrowserSecurity.Browser;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    /// <summary>Displays metadata-only Browser Defender inventory without equating unread profiles with safe or empty browsers.</summary>
    public partial class BrowserSecurityViewModel : ObservableObject
    {
        private readonly IBrowserSecurityScanner? _browserScanner;
        private List<BrowserProfile> _allProfiles = new();
        private int _loading;

        [ObservableProperty]
        private string pageTitle = "Browser Defender";

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

        [ObservableProperty]
        private string profileCoverageMessage = "Eklenti envanteri henüz incelenmedi.";

        /// <summary>Aggregate authorized-root coverage, independent of the selected profile's metadata rows.</summary>
        [ObservableProperty]
        private string inventoryCoverageMessage = "Genel envanter kapsamı henüz gözlenmedi.";

        /// <summary>Starts the initial bounded metadata refresh; no browser extension or profile setting is changed.</summary>
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
                HasNoExtensions = Extensions.Count == 0 && value.MetadataCoverage == BrowserMetadataCoverage.Complete;
                ProfileCoverageMessage = value.MetadataCoverage switch
                {
                    BrowserMetadataCoverage.Complete => "Eklenti metaverisi incelendi; bu, dosyaların temiz olduğu veya çerez erişiminin engellendiği anlamına gelmez.",
                    BrowserMetadataCoverage.Partial => "Bu profil kısmen incelendi. Görünmeyen veya okunamayan eklentiler olabilir.",
                    BrowserMetadataCoverage.NotPresent => "Seçilen profil bulunamadı.",
                    _ => "Bu profilin eklenti listesi incelenemedi; temiz kabul edilmedi."
                };
                SelectedExtension = Extensions.FirstOrDefault();
            }
            else
            {
                Extensions.Clear();
                HasNoExtensions = false;
                ProfileCoverageMessage = "İncelenebilen bir profil seçilmedi.";
                SelectedExtension = null;
            }
        }

        /// <summary>Coalesces concurrent refresh requests and displays incomplete roots separately from verified empty metadata.</summary>
        [RelayCommand]
        public async Task LoadBrowserDataAsync()
        {
            if (_browserScanner == null)
            {
                StatusMessage = "Browser Defender metaveri okuyucusu kullanılamıyor.";
                return;
            }

            if (Interlocked.Exchange(ref _loading, 1) != 0) return;
            IsLoading = true;
            StatusMessage = "Yüklü tarayıcılar ve eklentiler taranıyor...";
            InventoryCoverageMessage = "Genel envanter yenileniyor; önceki profil satırları güncel gözlem sayılmaz.";
            try
            {
                BrowserInventoryCoverage? inventoryCoverage = null;
                if (_browserScanner is IBrowserInventoryScanner inventoryScanner)
                {
                    var inventory = await inventoryScanner.ScanInventoryAsync();
                    _allProfiles = inventory.Profiles.Select(item => item.Profile).ToList();
                    inventoryCoverage = inventory.Coverage;
                    InventoryCoverageMessage = DescribeInventoryCoverage(inventory.Coverage);
                }
                else
                {
                    _allProfiles = await _browserScanner.ScanAllBrowsersAsync();
                    InventoryCoverageMessage = "Genel kök kapsamı bu okuyucudan alınamadı; profil satırları tüm tarayıcıları temsil etmeyebilir.";
                }
                ApplyInventory(inventoryCoverage);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Browser Defender UI inventory failed: {ex.GetType().Name}.");
                InventoryCoverageMessage = "Genel envanter yenilenemedi; mevcut profil satırları eski olabilir.";
                StatusMessage = $"Hata: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
                Volatile.Write(ref _loading, 0);
            }
        }

        private void ApplyInventory(BrowserInventoryCoverage? inventoryCoverage)
        {
                // Prefer profiles with observed extensions without calling them safe.
                var orderedProfiles = _allProfiles
                    .OrderByDescending(p => p.Extensions.Count > 0)
                    .ThenByDescending(p => p.Extensions.Count)
                    .ThenBy(p => p.BrowserType.ToString())
                    .ThenBy(p => p.ProfileName)
                    .ToList();

                Profiles = new ObservableCollection<BrowserProfile>(orderedProfiles);

                // Select an observed profile, never invent a fallback browser.
                SelectedProfile = Profiles.FirstOrDefault(p => p.Extensions.Count > 0) ?? Profiles.FirstOrDefault();

                int totalExt = _allProfiles.Sum(p => p.Extensions.Count);
                int suspiciousExt = _allProfiles.Sum(p => p.Extensions.Count(e =>
                    e.RiskLevel is Core.Enums.RiskLevel.Suspicious or Core.Enums.RiskLevel.HighRisk));
                int incompleteProfiles = _allProfiles.Count(p => p.MetadataCoverage != BrowserMetadataCoverage.Complete);

                if (Profiles.Count == 0)
                {
                    StatusMessage = inventoryCoverage == BrowserInventoryCoverage.NotPresent
                        ? "Yetkili konumlarda tarayıcı profili bulunamadı; bu bir güvenlik sonucu değildir."
                        : "Tarayıcı profilleri incelenemedi. Boş veya temiz oldukları doğrulanmadı.";
                    ProfileCoverageMessage = StatusMessage;
                }
                else if (SelectedProfile != null && SelectedProfile.Extensions.Count > 0)
                {
                    StatusMessage = $"{SelectedProfile.BrowserType} ({SelectedProfile.ProfileName}) tarayıcısında {SelectedProfile.Extensions.Count} eklenti bulundu ve otomatik seçildi. (Toplam: {_allProfiles.Count} profil, {totalExt} eklenti, {suspiciousExt} şüpheli).";
                }
                else
                {
                    StatusMessage = $"Toplam {_allProfiles.Count} profil ve {totalExt} eklenti bulundu ({suspiciousExt} şüpheli/yüksek yetkili).";
                }
                StatusMessage += $" {incompleteProfiles} profil kısmi/incelenemedi. Yalnız metaveri gözlemi; eklenti engelleme veya çerez koruma kapısı henüz bağlı değil.";
        }

        private static string DescribeInventoryCoverage(BrowserInventoryCoverage coverage) => coverage switch
        {
            BrowserInventoryCoverage.Complete => "Genel kapsam: istenen destekli metaveri okundu; dosyaların temiz olduğu kanıtlanmadı.",
            BrowserInventoryCoverage.Partial => "Genel kapsam: kısmi. Bazı tarayıcı konumları, profiller veya metaveri alanları incelenemedi.",
            BrowserInventoryCoverage.NotPresent => "Genel kapsam: yetkili konumlarda profil bulunamadı; güvenlik sonucu değildir.",
            _ => "Genel kapsam: incelenemedi. Görünen profil satırları tam envanter kanıtı değildir."
        };
    }
}
