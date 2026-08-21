using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    public class DnsProtectionService : IDnsProtectionService, IDisposable
    {
        private readonly ILogger<DnsProtectionService>? _logger;
        private readonly IWebShieldService _webShieldService;
        private readonly FileSystemWatcher? _hostsWatcher;
        private bool _isDisposed;

        private static readonly string HostsFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");

        private const string SinkholeMarkerHeader = "# --- ULTRON DEFENDER MALICIOUS DOMAIN SINKHOLE BEGIN ---";
        private const string SinkholeMarkerFooter = "# --- ULTRON DEFENDER MALICIOUS DOMAIN SINKHOLE END ---";

        public event Action<string>? OnHostsFileModified;

        public DnsProtectionService(
            IWebShieldService webShieldService,
            ILogger<DnsProtectionService>? logger = null)
        {
            _webShieldService = webShieldService;
            _logger = logger;

            try
            {
                var etcDir = Path.GetDirectoryName(HostsFilePath);
                if (Directory.Exists(etcDir))
                {
                    _hostsWatcher = new FileSystemWatcher(etcDir, "hosts")
                    {
                        NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                        EnableRaisingEvents = true
                    };

                    _hostsWatcher.Changed += (s, e) => OnHostsFileModified?.Invoke("Windows Hosts dosyası değiştirildi!");
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Failed to initialize hosts FileSystemWatcher");
            }
        }

        public Task<List<DnsAdapterInfo>> GetNetworkAdaptersDnsAsync(CancellationToken cancellationToken = default)
        {
            var result = new List<DnsAdapterInfo>();

            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in interfaces)
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback || ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                    var ipProps = ni.GetIPProperties();
                    var dnsAddresses = ipProps.DnsAddresses.Select(ip => ip.ToString()).ToList();

                    var adapter = new DnsAdapterInfo
                    {
                        Id = ni.Id,
                        Name = ni.Name,
                        Description = ni.Description,
                        Status = ni.OperationalStatus.ToString(),
                        DnsServers = dnsAddresses
                    };

                    // Identify provider
                    if (dnsAddresses.Any(d => d == "1.1.1.1" || d == "1.0.0.1" || d == "2606:4700:4700::1111"))
                    {
                        adapter.IsSecureDns = true;
                        adapter.ProviderName = "Cloudflare Güvenli DNS (1.1.1.1)";
                    }
                    else if (dnsAddresses.Any(d => d == "9.9.9.9" || d == "149.112.112.112"))
                    {
                        adapter.IsSecureDns = true;
                        adapter.ProviderName = "Quad9 Zararlı Engelleyici DNS (9.9.9.9)";
                    }
                    else if (dnsAddresses.Any(d => d == "8.8.8.8" || d == "8.8.4.4"))
                    {
                        adapter.IsSecureDns = true;
                        adapter.ProviderName = "Google Public DNS (8.8.8.8)";
                    }
                    else
                    {
                        adapter.IsSecureDns = false;
                        adapter.ProviderName = dnsAddresses.Count > 0 ? "Varsayılan / Servis Sağlayıcı (ISP)" : "Otomatik (DHCP)";
                    }

                    result.Add(adapter);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to enumerate network adapters DNS");
            }

            return Task.FromResult(result);
        }

        public async Task<bool> SetSecureDnsAsync(string adapterName, SecureDnsProvider provider, CancellationToken cancellationToken = default)
        {
            return await Task.Run(() =>
            {
                try
                {
                    string primaryDns = "";
                    string secondaryDns = "";

                    switch (provider)
                    {
                        case SecureDnsProvider.Cloudflare:
                            primaryDns = "1.1.1.1";
                            secondaryDns = "1.0.0.1";
                            break;
                        case SecureDnsProvider.Quad9:
                            primaryDns = "9.9.9.9";
                            secondaryDns = "149.112.112.112";
                            break;
                        case SecureDnsProvider.Google:
                            primaryDns = "8.8.8.8";
                            secondaryDns = "8.8.4.4";
                            break;
                        case SecureDnsProvider.Automatic:
                            RunNetshCommand($"interface ipv4 set dns name=\"{adapterName}\" source=dhcp");
                            return true;
                    }

                    // Set primary DNS
                    RunNetshCommand($"interface ipv4 set dns name=\"{adapterName}\" static {primaryDns} primary");

                    // Set secondary DNS
                    if (!string.IsNullOrEmpty(secondaryDns))
                    {
                        RunNetshCommand($"interface ipv4 add dns name=\"{adapterName}\" {secondaryDns} index=2");
                    }

                    return true;
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to set secure DNS on adapter {Adapter}", adapterName);
                    return false;
                }
            }, cancellationToken);
        }

        public async Task<HostsIntegrityStatus> CheckHostsFileIntegrityAsync(CancellationToken cancellationToken = default)
        {
            var status = new HostsIntegrityStatus { IsIntact = true };

            if (!File.Exists(HostsFilePath))
            {
                return status;
            }

            try
            {
                var lines = await File.ReadAllLinesAsync(HostsFilePath, cancellationToken);
                status.TotalEntries = lines.Count(l => !string.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith("#"));

                bool inSinkholeBlock = false;
                var protectedTargets = new[] { "windowsupdate.com", "microsoft.com", "update.microsoft.com", "google.com", "symantec.com", "kaspersky.com", "bitdefender.com" };

                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (trimmed == SinkholeMarkerHeader)
                    {
                        inSinkholeBlock = true;
                        continue;
                    }
                    if (trimmed == SinkholeMarkerFooter)
                    {
                        inSinkholeBlock = false;
                        continue;
                    }

                    if (inSinkholeBlock && !trimmed.StartsWith("#"))
                    {
                        status.SinkholedMaliciousEntries++;
                        continue;
                    }

                    if (!trimmed.StartsWith("#") && !string.IsNullOrWhiteSpace(trimmed))
                    {
                        var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2)
                        {
                            var ip = parts[0];
                            var domain = parts[1].ToLowerInvariant();

                            if (protectedTargets.Any(pt => domain.Contains(pt)))
                            {
                                status.IsIntact = false;
                                status.SuspiciousHijackedEntries.Add($"{domain} -> {ip} (Güvenlik / Güncelleme Engelleme)");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to inspect hosts file integrity");
            }

            return status;
        }

        public async Task<bool> ApplyMaliciousDomainSinkholeAsync(CancellationToken cancellationToken = default)
        {
            if (!File.Exists(HostsFilePath)) return false;

            try
            {
                var blockedList = _webShieldService.GetBlockedDomains();
                if (blockedList.Count == 0) return true;

                var existingContent = await File.ReadAllTextAsync(HostsFilePath, cancellationToken);

                // Strip existing sinkhole block if present
                var cleanContent = RemoveSinkholeBlock(existingContent);

                var sb = new StringBuilder(cleanContent);
                sb.AppendLine();
                sb.AppendLine(SinkholeMarkerHeader);
                foreach (var domain in blockedList)
                {
                    sb.AppendLine($"0.0.0.0 {domain}");
                    sb.AppendLine($"0.0.0.0 www.{domain}");
                }
                sb.AppendLine(SinkholeMarkerFooter);

                await File.WriteAllTextAsync(HostsFilePath, sb.ToString(), cancellationToken);
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to write sinkhole block to hosts file (Administrator privileges required).");
                return false;
            }
        }

        public async Task<bool> RemoveMaliciousDomainSinkholeAsync(CancellationToken cancellationToken = default)
        {
            if (!File.Exists(HostsFilePath)) return false;

            try
            {
                var existingContent = await File.ReadAllTextAsync(HostsFilePath, cancellationToken);
                var cleanContent = RemoveSinkholeBlock(existingContent);
                await File.WriteAllTextAsync(HostsFilePath, cleanContent, cancellationToken);
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to remove sinkhole block from hosts file");
                return false;
            }
        }

        private static string RemoveSinkholeBlock(string content)
        {
            var startIndex = content.IndexOf(SinkholeMarkerHeader, StringComparison.Ordinal);
            if (startIndex >= 0)
            {
                var endIndex = content.IndexOf(SinkholeMarkerFooter, startIndex, StringComparison.Ordinal);
                if (endIndex >= 0)
                {
                    var removeLength = (endIndex + SinkholeMarkerFooter.Length) - startIndex;
                    return content.Remove(startIndex, removeLength).TrimEnd();
                }
            }
            return content.TrimEnd();
        }

        private static void RunNetshCommand(string arguments)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(3000);
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _hostsWatcher?.Dispose();
            _isDisposed = true;
        }
    }
}
