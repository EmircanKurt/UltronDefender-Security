using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

/// <summary>Resolves local fixed/removable volumes independently of drive letters; network paths require explicit selection.</summary>
public interface IScanVolumeTargetResolver
{
    /// <summary>Returns ready local volume roots and explicit enumeration or readiness gaps without starting any scan.</summary>
    Task<ScanVolumeTargetResolution> ResolveAsync(CancellationToken cancellationToken = default);
}
