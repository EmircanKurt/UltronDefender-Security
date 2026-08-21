using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Performance.Network
{
    public class NetworkMonitorService : INetworkMonitor
    {
        private readonly ILogger<NetworkMonitorService>? _logger;

        public NetworkMonitorService(ILogger<NetworkMonitorService>? logger = null)
        {
            _logger = logger;
        }

        public Task<List<NetworkConnection>> GetActiveConnectionsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var rawConnections = TcpTableInterop.GetAllTcpConnections();

                // Enrich with Process Name & Path
                foreach (var conn in rawConnections)
                {
                    if (conn.PID > 0)
                    {
                        try
                        {
                            using var proc = System.Diagnostics.Process.GetProcessById(conn.PID);
                            conn.ProcessName = proc.ProcessName;
                            try
                            {
                                conn.ProcessPath = proc.MainModule?.FileName ?? string.Empty;
                            }
                            catch { }
                        }
                        catch
                        {
                            conn.ProcessName = $"[PID: {conn.PID}]";
                        }
                    }
                    else
                    {
                        conn.ProcessName = "System / Idle";
                    }
                }

                return Task.FromResult(rawConnections.OrderBy(c => c.ProcessName).ToList());
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to retrieve network connections.");
                return Task.FromResult(new List<NetworkConnection>());
            }
        }

        public async Task<List<NetworkConnection>> GetConnectionsByProcessAsync(int pid, CancellationToken cancellationToken = default)
        {
            var all = await GetActiveConnectionsAsync(cancellationToken);
            return all.Where(c => c.PID == pid).ToList();
        }
    }
}
