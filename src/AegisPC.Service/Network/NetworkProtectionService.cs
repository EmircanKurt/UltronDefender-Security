using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Network;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Network
{
    public interface INetworkProtectionService : IDisposable
    {
        bool IsRunning { get; }
        bool IsDnsSinkholeActive { get; }
        DnsFilterStatistics GetStatistics();
        void Start();
        void Stop();
        DnsResolutionResult EvaluateDomain(string domain);
        NetworkConnectionVerdict? AnalyzeFlow(NetworkFlowEvent flow);
    }

    /// <summary>
    /// Ağ ve DNS Koruma Servisi.
    /// Layer 7 DNS Sinkhole (Hosts enjeksiyonu + DoH koruması), zararlı alan adı engelleme
    /// ve şüpheli C2 / giden ağ akışı telemetrisini koordine eder.
    /// Not: Bu servis kullanıcı modunda çalışmakta olup, kernel WFP (Windows Filtering Platform)
    /// filtreleme sürücüsü yerine DNS seviyesinde engelleme ve soket telemetrisi sağlar.
    /// </summary>
    public class NetworkProtectionService : INetworkProtectionService
    {
        private readonly ILogger<NetworkProtectionService>? _logger;
        private readonly DnsFilterService _dnsFilterService;
        private readonly INetworkProcessCorrelator? _processCorrelator;
        private bool _isRunning;
        private readonly object _lock = new();

        public bool IsRunning => _isRunning;
        public bool IsDnsSinkholeActive => _dnsFilterService.HostsHelper.IsSinkholeActive();

        public NetworkProtectionService(
            DnsFilterService dnsFilterService,
            INetworkProcessCorrelator? processCorrelator = null,
            ILogger<NetworkProtectionService>? logger = null)
        {
            _dnsFilterService = dnsFilterService ?? throw new ArgumentNullException(nameof(dnsFilterService));
            _processCorrelator = processCorrelator;
            _logger = logger;
        }

        public void Start()
        {
            lock (_lock)
            {
                if (_isRunning) return;

                _logger?.LogInformation("NetworkProtectionService baslatiliyor: DNS Sinkhole ve Alan Adi Filtreleme devrede.");

                try
                {
                    // Hosts dosyasındaki zararlı alan adı sinkhole girdilerini doğrula
                    int entries = _dnsFilterService.HostsHelper.GetSinkholeEntryCount();
                    _logger?.LogInformation("DNS Sinkhole aktif: {Count} alan adi yonlendiriliyor.", entries);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "DNS Sinkhole baslatilirken uyari.");
                }

                _isRunning = true;
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning) return;
                _isRunning = false;
                _logger?.LogInformation("NetworkProtectionService durduruldu.");
            }
        }

        public DnsResolutionResult EvaluateDomain(string domain)
        {
            return _dnsFilterService.ResolveDomainAsync(domain).GetAwaiter().GetResult();
        }

        public NetworkConnectionVerdict? AnalyzeFlow(NetworkFlowEvent flow)
        {
            if (flow == null) return null;

            // Alan adı engelli mi kontrol et
            if (!string.IsNullOrWhiteSpace(flow.DestinationDomain))
            {
                if (_dnsFilterService.IsDomainBlocked(flow.DestinationDomain, out var cat, out var reason))
                {
                    return new NetworkConnectionVerdict
                    {
                        IsSuspicious = true,
                        IsC2Beaconing = (cat == UrlBlockCategory.C2Server),
                        RiskScore = 90,
                        ThreatTitle = $"Engellenen Zararlı Alan Adı: {flow.DestinationDomain}",
                        ThreatCategory = cat.ToString(),
                        Explanation = reason
                    };
                }
            }

            // Süreç korelatörü varsa C2 / beaconing analizi yap
            if (_processCorrelator != null)
            {
                return _processCorrelator.CorrelateFlow(flow);
            }

            return new NetworkConnectionVerdict
            {
                IsSuspicious = false,
                RiskScore = 0,
                ThreatTitle = "Clean Flow"
            };
        }

        public DnsFilterStatistics GetStatistics()
        {
            return _dnsFilterService.GetStatistics();
        }

        public void Dispose()
        {
            Stop();
            _dnsFilterService?.Dispose();
        }
    }
}
