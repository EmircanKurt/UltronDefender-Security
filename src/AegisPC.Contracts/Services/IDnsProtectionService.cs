using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services
{
    public enum SecureDnsProvider
    {
        Cloudflare, // 1.1.1.1, 1.0.0.1
        Google,     // 8.8.8.8, 8.8.4.4
        Quad9,      // 9.9.9.9, 149.112.112.112 (Malware Blocking)
        Automatic   // DHCP
    }

    public class DnsAdapterInfo
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public List<string> DnsServers { get; set; } = new();
        public bool IsSecureDns { get; set; }
        public bool HasInternetGateway { get; set; }
        public string ProviderName { get; set; } = "Bilinmeyen / Servis Sağlayıcı";
    }

    public class HostsIntegrityStatus
    {
        public bool IsIntact { get; set; }
        public int TotalEntries { get; set; }
        public int SinkholedMaliciousEntries { get; set; }
        public List<string> SuspiciousHijackedEntries { get; set; } = new();
        public DateTime LastCheckedAt { get; set; } = DateTime.UtcNow;
    }

    public interface IDnsProtectionService
    {
        Task<List<DnsAdapterInfo>> GetNetworkAdaptersDnsAsync(CancellationToken cancellationToken = default);
        Task<bool> SetSecureDnsAsync(string adapterName, SecureDnsProvider provider, CancellationToken cancellationToken = default);
        Task<HostsIntegrityStatus> CheckHostsFileIntegrityAsync(CancellationToken cancellationToken = default);
        Task<bool> ApplyMaliciousDomainSinkholeAsync(CancellationToken cancellationToken = default);
        Task<bool> RemoveMaliciousDomainSinkholeAsync(CancellationToken cancellationToken = default);
        event Action<string>? OnHostsFileModified;
    }
}
