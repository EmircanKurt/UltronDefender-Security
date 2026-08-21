using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface INetworkMonitor
{
    Task<List<NetworkConnection>> GetActiveConnectionsAsync(CancellationToken cancellationToken = default);
    Task<List<NetworkConnection>> GetConnectionsByProcessAsync(int pid, CancellationToken cancellationToken = default);
}
