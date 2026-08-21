using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services;

public interface IElevationService
{
    bool IsElevated { get; }
    Task<bool> RequestElevatedActionAsync(string command, string args, CancellationToken cancellationToken = default);
}
