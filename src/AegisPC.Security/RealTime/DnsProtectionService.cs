using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
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
                        InternalBufferSize = 16384,
                        EnableRaisingEvents = true
                    };

                    _hostsWatcher.Changed += (s, e) => OnHostsFileModified?.Invoke("Windows Hosts dosyası değiştirildi!");
                    _hostsWatcher.Error += (s, e) =>
                    {
                        try
                        {
                            if (s is FileSystemWatcher fsw)
                            {
                                fsw.EnableRaisingEvents = false;
                                fsw.EnableRaisingEvents = true;
                            }
                        }
                        catch { }
                    };
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
                    var dnsAddresses = ipProps.DnsAddresses
                        .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork || ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        .Select(ip => ip.ToString())
                        .ToList();

                    var hasGateway = ipProps.GatewayAddresses.Any(g => g?.Address != null && g.Address.ToString() != "0.0.0.0" && !string.IsNullOrWhiteSpace(g.Address.ToString()));

                    var adapter = new DnsAdapterInfo
                    {
                        Id = ni.Id,
                        Name = ni.Name,
                        Description = ni.Description,
                        Status = ni.OperationalStatus.ToString(),
                        DnsServers = dnsAddresses,
                        HasInternetGateway = hasGateway
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

                // Sort: Active gateway adapters come first
                result = result.OrderByDescending(a => a.HasInternetGateway).ThenBy(a => a.Name).ToList();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to enumerate network adapters DNS");
            }

            return Task.FromResult(result);
        }

        public async Task<bool> SetSecureDnsAsync(string adapterName, SecureDnsProvider provider, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(adapterName)) return false;

            return await Task.Run(async () =>
            {
                try
                {
                    string primaryDns = "";
                    string secondaryDns = "";
                    bool isDhcp = (provider == SecureDnsProvider.Automatic);

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
                    }

                    bool executed = false;
                    bool isAdmin = IsCurrentProcessAdmin();

                    if (isAdmin)
                    {
                        // 1. Current process is Administrator: Run netsh directly
                        if (isDhcp)
                        {
                            var r = RunProcess("netsh.exe", $"interface ipv4 set dns name=\"{adapterName}\" source=dhcp");
                            if (r.ExitCode == 0) executed = true;
                            else
                            {
                                var ps = RunProcess("powershell.exe", $"-NoProfile -NonInteractive -Command \"Set-DnsClientServerAddress -InterfaceAlias '{adapterName}' -ResetServerAddresses\"");
                                if (ps.ExitCode == 0) executed = true;
                            }
                        }
                        else
                        {
                            var r1 = RunProcess("netsh.exe", $"interface ipv4 set dns name=\"{adapterName}\" static {primaryDns} primary");
                            if (r1.ExitCode == 0)
                            {
                                executed = true;
                                if (!string.IsNullOrEmpty(secondaryDns))
                                {
                                    RunProcess("netsh.exe", $"interface ipv4 add dns name=\"{adapterName}\" {secondaryDns} index=2");
                                }
                            }
                            else
                            {
                                var ips = string.IsNullOrEmpty(secondaryDns) ? $"'{primaryDns}'" : $"'{primaryDns}','{secondaryDns}'";
                                var ps = RunProcess("powershell.exe", $"-NoProfile -NonInteractive -Command \"Set-DnsClientServerAddress -InterfaceAlias '{adapterName}' -ServerAddresses ({ips})\"");
                                if (ps.ExitCode == 0) executed = true;
                            }
                        }
                    }
                    else
                    {
                        // 2. Not Administrator: Elevate via AegisPC.ElevatedHelper or UAC Prompt
                        var helperPath = GetElevatedHelperPath();
                        if (helperPath != null)
                        {
                            string arg = isDhcp ? "dhcp" : $"{primaryDns},{secondaryDns}".TrimEnd(',');
                            var psi = new ProcessStartInfo
                            {
                                FileName = helperPath,
                                Arguments = $"--set-dns \"{adapterName}\" \"{arg}\"",
                                UseShellExecute = true,
                                Verb = "runas"
                            };
                            using var proc = Process.Start(psi);
                            if (proc != null)
                            {
                                await proc.WaitForExitAsync(cancellationToken);
                                executed = (proc.ExitCode == 0);
                            }
                        }
                        else
                        {
                            // Fallback to elevated PowerShell
                            string psCmd = isDhcp
                                ? $"Set-DnsClientServerAddress -InterfaceAlias '{adapterName}' -ResetServerAddresses"
                                : $"Set-DnsClientServerAddress -InterfaceAlias '{adapterName}' -ServerAddresses @('{primaryDns}'{(!string.IsNullOrEmpty(secondaryDns) ? $",'{secondaryDns}'" : "")})";

                            var psi = new ProcessStartInfo
                            {
                                FileName = "powershell.exe",
                                Arguments = $"-NoProfile -WindowStyle Hidden -Command \"{psCmd}; ipconfig /flushdns\"",
                                UseShellExecute = true,
                                Verb = "runas"
                            };
                            using var proc = Process.Start(psi);
                            if (proc != null)
                            {
                                await proc.WaitForExitAsync(cancellationToken);
                                executed = (proc.ExitCode == 0);
                            }
                        }
                    }

                    // 3. DNS Cache Temizleme (Flush DNS)
                    FlushDnsResolverCache();

                    // 4. Değişikliğin Doğrulanması (Verification)
                    await Task.Delay(400, cancellationToken);
                    bool verified = false;
                    for (int i = 0; i < 4; i++)
                    {
                        var currentAdapters = await GetNetworkAdaptersDnsAsync(cancellationToken);
                        var target = currentAdapters.FirstOrDefault(a => a.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase) || a.Id == adapterName);
                        if (target != null)
                        {
                            if (isDhcp)
                            {
                                if (!target.IsSecureDns || target.DnsServers.Count == 0 || target.ProviderName.Contains("Otomatik") || target.ProviderName.Contains("Varsayılan"))
                                {
                                    verified = true;
                                    break;
                                }
                            }
                            else if (provider == SecureDnsProvider.Cloudflare && target.DnsServers.Any(d => d.StartsWith("1.1.1.1") || d.StartsWith("1.0.0.1")))
                            {
                                verified = true;
                                break;
                            }
                            else if (provider == SecureDnsProvider.Quad9 && target.DnsServers.Any(d => d.StartsWith("9.9.9.9") || d.StartsWith("149.112.112.112")))
                            {
                                verified = true;
                                break;
                            }
                            else if (provider == SecureDnsProvider.Google && target.DnsServers.Any(d => d.StartsWith("8.8.8.8") || d.StartsWith("8.8.4.4")))
                            {
                                verified = true;
                                break;
                            }
                        }
                        await Task.Delay(300, cancellationToken);
                    }

                    return verified || executed;
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

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache", SetLastError = true)]
        private static extern int DnsFlushResolverCache();

        public static void FlushDnsResolverCache()
        {
            try
            {
                DnsFlushResolverCache();
            }
            catch { }

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ipconfig.exe",
                    Arguments = "/flushdns",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(2000);
            }
            catch { }
        }

        private static bool IsCurrentProcessAdmin()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private static string? GetElevatedHelperPath()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var candidates = new[]
            {
                Path.Combine(baseDir, "Helpers", "AegisPC.ElevatedHelper.exe"),
                Path.Combine(baseDir, "AegisPC.ElevatedHelper.exe"),
                Path.Combine(baseDir, "tools", "AegisPC.ElevatedHelper", "bin", "Release", "net8.0-windows", "AegisPC.ElevatedHelper.exe"),
                Path.Combine(baseDir, "tools", "AegisPC.ElevatedHelper", "bin", "Debug", "net8.0-windows", "AegisPC.ElevatedHelper.exe")
            };

            return candidates.FirstOrDefault(File.Exists);
        }

        private static (int ExitCode, string Output, string Error) RunProcess(string fileName, string args)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            if (proc == null) return (-1, "", "Process başlatılamadı.");
            var output = proc.StandardOutput.ReadToEnd();
            var error = proc.StandardError.ReadToEnd();
            proc.WaitForExit(5000);
            return (proc.ExitCode, output, error);
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _hostsWatcher?.Dispose();
            _isDisposed = true;
        }
    }
}
