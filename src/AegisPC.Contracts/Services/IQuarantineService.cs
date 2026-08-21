using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IQuarantineService
{
    Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken = default);
    Task<bool> RestoreFileAsync(int id, CancellationToken cancellationToken = default);
    Task<bool> RestoreFileAsync(int id, string? customDestinationPath, CancellationToken cancellationToken = default);
    Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default);
    Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default);
    Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default);
}
