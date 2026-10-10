using System;
using System.IO;
using System.Threading;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

public partial class DirectoryWalker
{
    private readonly AegisPC.Contracts.Services.IScanTargetResolver _scanTargets;
    private readonly AegisPC.Contracts.Services.IScanVolumeTargetResolver _volumeTargets;
    private readonly IDirectoryWalker? _quickPreflight;
    /// <summary>Uses explicit current-user/SYSTEM profile resolution; construction performs no live enumeration.</summary>
    public DirectoryWalker(AegisPC.Contracts.Services.IScanTargetResolver? scanTargets = null,
        AegisPC.Contracts.Services.IScanVolumeTargetResolver? volumeTargets = null,
        IDirectoryWalker? quickPreflight = null)
    {
        _scanTargets = scanTargets ?? new WindowsScanTargetResolver();
        _volumeTargets = volumeTargets ?? new WindowsScanVolumeTargetResolver();
        _quickPreflight = quickPreflight;
    }
    private readonly AsyncLocal<ScanCoverageSummary?> _coverage = new();

    /// <inheritdoc />
    public IDisposable BeginCoverage(ScanCoverageSummary summary)
    {
        ArgumentNullException.ThrowIfNull(summary);
        var previous = _coverage.Value;
        _coverage.Value = summary;
        return new CoverageScope(() => _coverage.Value = previous);
    }

    private sealed class CoverageScope(Action restore) : IDisposable
    {
        private Action? _restore = restore;
        public void Dispose() => Interlocked.Exchange(ref _restore, null)?.Invoke();
    }
}
