using System;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Security.RealTime;

/// <summary>Observes one media insertion and scans existing contents without executing them.</summary>
public interface IRemovableMediaProtection
{
    /// <summary>Immutable snapshots of current insertion jobs, including partial content coverage.</summary>
    System.Collections.Generic.IReadOnlyList<AegisPC.Core.Models.Devices.MediaInspectionSnapshot> GetMediaInspections();
    /// <summary>Attaches the watcher first, then streams initial contents using the common verdict and action pipeline.</summary>
    Task InspectMediaAsync(string volumePath, Guid insertionGeneration, CancellationToken cancellationToken);
    /// <summary>Removes the watcher only if the specified insertion still owns it.</summary>
    void RemoveMedia(Guid insertionGeneration);
}
