using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

/// <summary>Starts background work without taking ownership of an existing manual scan.</summary>
public interface IBackgroundScanCoordinator
{
    /// <summary>Atomically starts an owned scan, or returns null when another scan is active.</summary>
    Task<ScanResult?> TryStartBackgroundScanAsync(ScanType scanType, CancellationToken cancellationToken);
    /// <summary>Invokes the callback only after claiming an idle coordinator and before scanning begins.</summary>
    Task<ScanResult?> TryStartBackgroundScanAsync(ScanType scanType, CancellationToken cancellationToken,
        System.Action beforeOwnedScanStarts) => TryStartBackgroundScanAsync(scanType, cancellationToken);
}
