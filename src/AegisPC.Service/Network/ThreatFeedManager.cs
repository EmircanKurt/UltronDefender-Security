using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Service.Update;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Network
{
    /// <summary>
    /// Çevrimdışı ve çevrimiçi tehdit besleme orkestratörü (ThreatFeedManager).
    /// MalwareBazaar, URLhaus, abuse.ch ve yerel kara liste dosyalarının
    /// DnsFilterService ve Hosts dosyası ile senkronizasyonunu yönetir.
    /// </summary>
    public class ThreatFeedManager
    {
        private readonly DnsFilterService _dnsFilterService;
        private readonly ThreatFeedUpdater? _feedUpdater;
        private readonly ILogger<ThreatFeedManager>? _logger;

        public ThreatFeedManager(
            DnsFilterService? dnsFilterService = null,
            ThreatFeedUpdater? feedUpdater = null,
            ILogger<ThreatFeedManager>? logger = null)
        {
            _dnsFilterService = dnsFilterService ?? new DnsFilterService();
            _feedUpdater = feedUpdater;
            _logger = logger;
        }

        /// <summary>
        /// Tüm yerel kara listeleri hosts dosyasına sinkhole olarak yazar ve DNS önbelleğini tazeler.
        /// </summary>
        public bool ApplyOfflineBlocklistsToHosts(SinkholeIpMode ipMode = SinkholeIpMode.Loopback)
        {
            _logger?.LogInformation("ThreatFeedManager: Yerel tehdit listeleri hosts dosyasına aktarılıyor...");
            return _dnsFilterService.SyncWithHostsFile(ipMode);
        }

        /// <summary>
        /// Hosts dosyasındaki sinkhole bloğunu kaldırır.
        /// </summary>
        public bool RemoveOfflineBlocklistsFromHosts()
        {
            _logger?.LogInformation("ThreatFeedManager: Hosts dosyasındaki sinkhole kaldırılıyor...");
            return _dnsFilterService.RemoveFromHostsFile();
        }

        /// <summary>
        /// İnternet bağlantısı mevcutsa açık kaynak tehdit beslemelerini günceller,
        /// ardından DnsFilterService ve hosts dosyasını yeni kurallarla günceller.
        /// </summary>
        public async Task<int> UpdateFeedsAndSyncAsync(bool force = false, CancellationToken cancellationToken = default)
        {
            int updatedCount = 0;
            if (_feedUpdater != null)
            {
                try
                {
                    _logger?.LogInformation("ThreatFeedManager: Tehdit istihbaratı güncellemeleri kontrol ediliyor...");
                    updatedCount = await _feedUpdater.UpdateFromMalwareBazaarAsync(force, cancellationToken: cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Tehdit beslemesi çevrimiçi güncellenirken hata oluştu.");
                }
            }

            // Yerel kuralları tazele
            _dnsFilterService.ReloadRules();

            // Hosts dosyası ile senkronize et
            _dnsFilterService.SyncWithHostsFile();

            return updatedCount;
        }

        public DnsFilterStatistics GetCurrentStatistics()
        {
            return _dnsFilterService.GetStatistics();
        }
    }
}
