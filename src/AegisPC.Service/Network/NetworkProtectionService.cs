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
        bool IsWfpActive { get; }
        IWfpEnforcementService? WfpEnforcement { get; }
        DnsFilterStatistics GetStatistics();
        void Start();
        void Stop();
        DnsResolutionResult EvaluateDomain(string domain);
        NetworkConnectionVerdict? AnalyzeFlow(NetworkFlowEvent flow);
    }

    /// <summary>
    /// Ağ ve DNS Koruma Servisi.
    /// Layer 7 DNS Sinkhole (Hosts enjeksiyonu + DoH koruması), zararlı alan adı engelleme,
    /// WFP (Windows Filtering Platform) ALE giden IP engelleme ve şüpheli C2 telemetrisini koordine eder.
    /// </summary>
    public class NetworkProtectionService : INetworkProtectionService
    {
        private readonly ILogger<NetworkProtectionService>? _logger;
        private readonly DnsFilterService _dnsFilterService;
        private readonly INetworkProcessCorrelator? _processCorrelator;
        private readonly IWfpEnforcementService? _wfpEnforcement;
        private bool _isRunning;
        private readonly object _lock = new();

        public bool IsRunning => _isRunning;
        public bool IsDnsSinkholeActive => _dnsFilterService.HostsHelper.IsSinkholeActive();
        public bool IsWfpActive => _wfpEnforcement?.IsWfpAvailable ?? false;
        public IWfpEnforcementService? WfpEnforcement => _wfpEnforcement;

        public NetworkProtectionService(
            DnsFilterService dnsFilterService,
            INetworkProcessCorrelator? processCorrelator = null,
            IWfpEnforcementService? wfpEnforcement = null,
            ILogger<NetworkProtectionService>? logger = null)
        {
            _dnsFilterService = dnsFilterService ?? throw new ArgumentNullException(nameof(dnsFilterService));
            _processCorrelator = processCorrelator;
            _wfpEnforcement = wfpEnforcement;
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

            NetworkConnectionVerdict verdict;

            // Alan adı engelli mi kontrol et
            if (!string.IsNullOrWhiteSpace(flow.DestinationDomain) &&
                _dnsFilterService.IsDomainBlocked(flow.DestinationDomain, out var cat, out var reason))
            {
                verdict = new NetworkConnectionVerdict
                {
                    IsSuspicious = true,
                    IsC2Beaconing = (cat == UrlBlockCategory.C2Server),
                    RiskScore = 90,
                    ThreatTitle = $"Engellenen Zararlı Alan Adı: {flow.DestinationDomain}",
                    ThreatCategory = cat.ToString(),
                    Explanation = reason
                };
            }
            // Süreç korelatörü varsa C2 / beaconing analizi yap
            else if (_processCorrelator != null)
            {
                verdict = _processCorrelator.CorrelateFlow(flow);
            }
            else
            {
                verdict = new NetworkConnectionVerdict
                {
                    IsSuspicious = false,
                    RiskScore = 0,
                    ThreatTitle = "Clean Flow"
                };
            }

            // Eğer akış şüpheli veya C2 olarak belirlendiyse, WFP ile IP seviyesinde giden paketi durdur
            if ((verdict.IsSuspicious || verdict.IsC2Beaconing) && !string.IsNullOrWhiteSpace(flow.DestinationIp))
            {
                _wfpEnforcement?.BlockOutboundIp(flow.DestinationIp, verdict.ThreatTitle);
            }

            return verdict;
        }

        public DnsFilterStatistics GetStatistics()
        {
            return _dnsFilterService.GetStatistics();
        }

        public void Dispose()
        {
            Stop();
            _dnsFilterService?.Dispose();
            _wfpEnforcement?.Dispose();
        }
    }
}
