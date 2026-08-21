using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services;

public interface IHashService
{
    Task<string> ComputeSha256Async(string filePath, CancellationToken cancellationToken = default);
    Task<string> ComputeSha1Async(string filePath, CancellationToken cancellationToken = default);
}
