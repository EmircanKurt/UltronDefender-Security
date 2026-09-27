using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services;

/// <summary>
/// Refreshes a process-local exclusion snapshot after another trusted process commits changes.
/// A failed refresh must retain the last committed snapshot and propagate the error to the caller.
/// </summary>
public interface IExclusionRefreshService
{
    /// <summary>Atomically replaces persisted exclusions after a successful database read; cancellation leaves the previous snapshot intact.</summary>
    Task ReloadAsync(CancellationToken cancellationToken = default);
}
