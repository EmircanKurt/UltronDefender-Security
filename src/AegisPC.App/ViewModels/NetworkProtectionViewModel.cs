using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.App.Services;
using AegisPC.Contracts.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class NetworkProtectionViewModel : ObservableObject
    {
        private readonly IDnsProtectionService _dnsService;
        private readonly IWebShieldService _webShieldService;
        private readonly IWindowsToastNotificationService? _toastService;

        [ObservableProperty] private string pageTitle = "Ağ, DNS ve Web Kalkanı";
        [ObservableProperty] private ObservableCollection<DnsAdapterInfo> adapters = new();
        [ObservableProperty] private DnsAdapterInfo? selectedAdapter;

        [ObservableProperty] private bool isHostsIntact = true;
        [ObservableProperty] private int hostsTotalEntries = 0;
        [ObservableProperty] private int sinkholedCount = 0;
        [ObservableProperty] private string hostsStatusText = "Hosts dosyası bütünlüğü doğrulanıyor...";

        // Interactive URL / Domain Analyzer
        [ObservableProperty] private string testUrlInput = "http://paypa1-verify-account.xyz/login.php";
        [ObservableProperty] private WebReputationVerdict? analysisVerdict;
        [ObservableProperty] private bool hasAnalysisResult = false;
        [ObservableProperty] private bool isAnalyzing = false;

        // Custom Lists
        [ObservableProperty] private ObservableCollection<string> bypassDomains = new();
        [ObservableProperty] private ObservableCollection<string> blockedDomains = new();
        [ObservableProperty] private string newDomainInput = string.Empty;
        [ObservableProperty] private string statusMessage = string.Empty;

        public NetworkProtectionViewModel(
            IDnsProtectionService dnsService,
            IWebShieldService webShieldService,
            IWindowsToastNotificationService? toastService = null)
        {
            _dnsService = dnsService;
            _webShieldService = webShieldService;
            _toastService = toastService;

            _ = InitializeDataAsync();
        }

        public async Task InitializeDataAsync()
        {
            await RefreshAdaptersAsync();
            await CheckHostsStatusAsync();
            RefreshCustomLists();
        }

        [RelayCommand]
        public async Task RefreshAdaptersAsync()
        {
            var list = await _dnsService.GetNetworkAdaptersDnsAsync();
            Adapters.Clear();
            foreach (var a in list)
            {
                Adapters.Add(a);
            }
            if (Adapters.Count > 0 && SelectedAdapter == null)
            {
                SelectedAdapter = Adapters.First();
            }
        }

        [RelayCommand]
        public async Task CheckHostsStatusAsync()
        {
            var status = await _dnsService.CheckHostsFileIntegrityAsync();
            IsHostsIntact = status.IsIntact;
            HostsTotalEntries = status.TotalEntries;
            SinkholedCount = status.SinkholedMaliciousEntries;

            if (!status.IsIntact)
            {
                HostsStatusText = $"⚠️ DİKKAT: {status.SuspiciousHijackedEntries.Count} şüpheli yönlendirme tespit edildi!";
            }
            else if (status.SinkholedMaliciousEntries > 0)
            {
                HostsStatusText = $"🛡️ Korumada: {status.SinkholedMaliciousEntries} bilinen zararlı alan adı yerel olarak engellendi.";
            }
            else
            {
                HostsStatusText = "✓ Windows Hosts dosyası standart ve temiz durumda.";
            }
        }

        [RelayCommand]
        public async Task SetDnsCloudflareAsync()
        {
            if (SelectedAdapter == null) return;
            var ok = await _dnsService.SetSecureDnsAsync(SelectedAdapter.Name, SecureDnsProvider.Cloudflare);
            if (ok)
            {
                StatusMessage = $"'{SelectedAdapter.Name}' için Cloudflare DNS (1.1.1.1) uygulandı.";
                _toastService?.ShowToast("DNS Koruması", StatusMessage, "Success");
                await RefreshAdaptersAsync();
            }
            else
            {
                StatusMessage = "DNS değiştirilemedi (Yönetici yetkisi gerekebilir).";
            }
        }

        [RelayCommand]
        public async Task SetDnsQuad9Async()
        {
            if (SelectedAdapter == null) return;
            var ok = await _dnsService.SetSecureDnsAsync(SelectedAdapter.Name, SecureDnsProvider.Quad9);
            if (ok)
            {
                StatusMessage = $"'{SelectedAdapter.Name}' için Quad9 Zararlı Engelleyici DNS (9.9.9.9) uygulandı.";
                _toastService?.ShowToast("DNS Koruması", StatusMessage, "Success");
                await RefreshAdaptersAsync();
            }
            else
            {
                StatusMessage = "DNS değiştirilemedi (Yönetici yetkisi gerekebilir).";
            }
        }

        [RelayCommand]
        public async Task SetDnsDhcpAsync()
        {
            if (SelectedAdapter == null) return;
            var ok = await _dnsService.SetSecureDnsAsync(SelectedAdapter.Name, SecureDnsProvider.Automatic);
            if (ok)
            {
                StatusMessage = $"'{SelectedAdapter.Name}' için DNS otomatik (DHCP) yapıldı.";
                _toastService?.ShowToast("DNS Koruması", StatusMessage, "Info");
                await RefreshAdaptersAsync();
            }
        }

        [RelayCommand]
        public async Task ApplySinkholeAsync()
        {
            var ok = await _dnsService.ApplyMaliciousDomainSinkholeAsync();
            if (ok)
            {
                StatusMessage = "Zararlı alan adları Windows Hosts dosyasına engellendi.";
                _toastService?.ShowToast("Ağ Koruması", StatusMessage, "Success");
                await CheckHostsStatusAsync();
            }
            else
            {
                StatusMessage = "Hosts dosyasına yazılamadı (Yönetici yetkisi gereklidir).";
            }
        }

        [RelayCommand]
        public async Task RemoveSinkholeAsync()
        {
            var ok = await _dnsService.RemoveMaliciousDomainSinkholeAsync();
            if (ok)
            {
                StatusMessage = "Zararlı alan adı sinkhole engeli kaldırıldı.";
                await CheckHostsStatusAsync();
            }
        }

        [RelayCommand]
        public async Task AnalyzeUrlAsync()
        {
            if (string.IsNullOrWhiteSpace(TestUrlInput)) return;

            IsAnalyzing = true;
            try
            {
                AnalysisVerdict = await _webShieldService.AnalyzeUrlAsync(TestUrlInput);
                HasAnalysisResult = true;
            }
            finally
            {
                IsAnalyzing = false;
            }
        }

        private void RefreshCustomLists()
        {
            BypassDomains.Clear();
            foreach (var d in _webShieldService.GetBypassDomains()) BypassDomains.Add(d);

            BlockedDomains.Clear();
            foreach (var d in _webShieldService.GetBlockedDomains()) BlockedDomains.Add(d);
        }

        [RelayCommand]
        public void AddBypassDomain()
        {
            if (string.IsNullOrWhiteSpace(NewDomainInput)) return;
            if (_webShieldService.AddBypassDomain(NewDomainInput))
            {
                RefreshCustomLists();
                NewDomainInput = string.Empty;
                StatusMessage = "Güvenilen alan adı eklendi.";
            }
        }

        [RelayCommand]
        public void AddBlockedDomain()
        {
            if (string.IsNullOrWhiteSpace(NewDomainInput)) return;
            if (_webShieldService.AddBlockedDomain(NewDomainInput, "Kullanıcı Tarafından Engellendi"))
            {
                RefreshCustomLists();
                NewDomainInput = string.Empty;
                StatusMessage = "Zararlı alan adı listesine eklendi.";
            }
        }

        [RelayCommand]
        public void RemoveBypassDomain(string domain)
        {
            if (_webShieldService.RemoveBypassDomain(domain))
            {
                RefreshCustomLists();
            }
        }
    }
}
