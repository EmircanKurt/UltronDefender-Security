using AegisPC.Contracts.Services;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;

namespace AegisPC.Security.RealTime;

/// <summary>Uses the same service-context profile resolver for initial startup and later shield activation.</summary>
public sealed class RansomwareShieldActivation
{
    private readonly IRansomwareProtectionEngine _engine;
    private readonly IScanTargetResolver _targets;
    private readonly SemaphoreSlim _gate = new(1, 1);
    /// <summary>Constructs the shared serialized lifecycle without starting watchers or deploying canaries.</summary>
    public RansomwareShieldActivation(IRansomwareProtectionEngine engine, IScanTargetResolver targets)
    { _engine = engine; _targets = targets; }
    /// <summary>Resolves documents before any start; missing inventory cannot turn into a healthy zero-root shield.</summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var targets = await _targets.ResolveAsync(cancellationToken).ConfigureAwait(false);
            foreach (var target in targets.DirectoryTargets.Where(x => x.Kind == ScanDirectoryKind.Documents))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (ImplicitLocalPathPolicy.IsEligible(target.Path) && Directory.Exists(target.Path)) _engine.AddProtectedDirectory(target.Path);
            }
            if (_engine is RansomwareProtectionEngine actual) actual.SetRootResolutionIncomplete(!targets.IsComplete);
            cancellationToken.ThrowIfCancellationRequested();
            _engine.StartShield();
            if (!_engine.IsShieldActive) throw new InvalidOperationException("Ransomware shield has no active observed roots.");
        }
        finally { _gate.Release(); }
    }
    /// <summary>Serializes explicit stops with activation to avoid a later start undoing a disable command.</summary>
    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { _engine.StopShield(); if (_engine.IsShieldActive) throw new InvalidOperationException("Ransomware observers remain active."); }
        finally { _gate.Release(); }
    }
}
