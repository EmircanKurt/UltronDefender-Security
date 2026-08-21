using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IAllowlistService
{
    Task<bool> IsAllowlistedAsync(string sha256, CancellationToken cancellationToken = default);
    Task AddToAllowlistAsync(AllowlistEntry entry, CancellationToken cancellationToken = default);
    Task RemoveFromAllowlistAsync(int id, CancellationToken cancellationToken = default);
    Task<List<AllowlistEntry>> GetAllowlistAsync(CancellationToken cancellationToken = default);
    Task<bool> CheckHashChangedAsync(AllowlistEntry entry, CancellationToken cancellationToken = default);
}
