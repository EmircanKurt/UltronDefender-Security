using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services;

public interface ISecureStorageService
{
    Task StoreSecretAsync(string key, string value, CancellationToken cancellationToken = default);
    Task<string?> GetSecretAsync(string key, CancellationToken cancellationToken = default);
    Task DeleteSecretAsync(string key, CancellationToken cancellationToken = default);
}
