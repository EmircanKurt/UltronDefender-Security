using Microsoft.Extensions.Logging;
using AegisPC.Contracts.Services;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.RealTime;

namespace AegisPC.Service.IPC;

/// <summary>Adapts singleton engines; optional activation and observed health are independent requirements.</summary>
internal sealed record ProtectionCommandComponent(Action Start, Action Stop, Func<bool> IsActive,
    bool RequireActivation = true, bool? ObserveForHealth = null);

/// <summary>Coordinates reversible enable and exhaustive disable for one protection command.</summary>
internal sealed class ProtectionCommandLifecycle
{
    private readonly IReadOnlyList<ProtectionCommandComponent> _components;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _commandGate = new(1, 1);
    private volatile bool _lastTransitionSucceeded = true;

    /// <summary>Creates the lifecycle over existing start/stop operations; callbacks must report actual state.</summary>
    public ProtectionCommandLifecycle(IReadOnlyList<ProtectionCommandComponent> components, ILogger logger)
    {
        _components = components;
        _logger = logger;
    }

    /// <summary>Observed listeners must be active; an optional startup failure preserves protection but reports partial health.</summary>
    public bool IsHealthy => _lastTransitionSucceeded && _components.Where(component => component.ObserveForHealth ?? component.RequireActivation)
        .All(component => component.IsActive());

    /// <summary>Builds adapters around the same worker-owned singleton engines and optional telemetry listeners.</summary>
    public static ProtectionCommandLifecycle Create(IRealTimeProtectionEngine realTime, IBackgroundProtectionService background,
        ILogger logger, IEtwPreExecProtectionService? preExec, AegisPC.Service.DriverBridge.IKernelBridge? kernel,
        AegisPC.Service.RealTime.EtwProcessMonitor? process, AegisPC.Service.RealTime.EtwImageLoadMonitor? image)
    {
        var components = new List<ProtectionCommandComponent>
        {
            new(realTime.Start, realTime.Stop, () => realTime.IsRunning),
            new(background.StartProtection, background.StopProtection, () => background.IsProtectionActive)
        };
        if (preExec != null) components.Add(new(preExec.Start, preExec.Stop, () => preExec.IsRunning,
            RequireActivation: false, ObserveForHealth: true));
        if (process != null) components.Add(new(process.Start, process.Stop, () => process.IsRunning,
            RequireActivation: false, ObserveForHealth: true));
        if (image != null) components.Add(new(image.Start, image.Stop, () => image.IsRunning,
            RequireActivation: false, ObserveForHealth: true));
        if (kernel != null) components.Add(new(() => { kernel.StartBridge(); }, kernel.StopBridge,
            () => kernel.IsDriverConnected, RequireActivation: false));
        return new ProtectionCommandLifecycle(components, logger);
    }

    /// <summary>Serializes commands; desired settings change only after success and persistence errors mark partial health.</summary>
    public async Task SetEnabledAsync(SettingsService settings, bool enabled)
    {
        await _commandGate.WaitAsync().ConfigureAwait(false);
        var previous = settings.Current.IsFileProtectionEnabled;
        try
        {
            if (enabled) Enable();
            else Disable();
            settings.Current.IsFileProtectionEnabled = enabled;
            await settings.SaveAsync().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Protection command or settings persistence failed.");
            settings.Current.IsFileProtectionEnabled = previous;
            MarkPersistenceFailure();
            throw;
        }
        finally { _commandGate.Release(); }
    }

    /// <summary>Starts inactive components; only required failures roll back this command's listeners, while optional failures report partial health.</summary>
    public void Enable()
    {
        _lastTransitionSucceeded = false;
        var started = new List<ProtectionCommandComponent>();
        var optionalStartupFailed = false;
        try
        {
            foreach (var component in _components)
            {
                if (component.IsActive()) continue;
                started.Add(component); // Include partially started components when Start throws.
                try { component.Start(); }
                catch (Exception exception) when (!component.RequireActivation)
                {
                    optionalStartupFailed = true;
                    _logger.LogWarning(exception, "Optional protection listener failed to start; required protection remains active.");
                    try { component.Stop(); }
                    catch (Exception cleanupException) { _logger.LogWarning(cleanupException, "Optional listener startup cleanup failed."); }
                    continue;
                }
                if (component.RequireActivation && !component.IsActive())
                    throw new InvalidOperationException("A required protection listener did not become active.");
            }
            _lastTransitionSucceeded = !optionalStartupFailed;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Protection enable failed; rolling back this command's listeners.");
            foreach (var component in started.AsEnumerable().Reverse())
            {
                try { component.Stop(); }
                catch (Exception rollbackException) { _logger.LogWarning(rollbackException, "Protection enable rollback failed."); }
            }
            throw;
        }
    }

    /// <summary>Attempts every stop even after errors; an active listener or failure makes the command fail.</summary>
    public void Disable()
    {
        _lastTransitionSucceeded = false;
        var failures = new List<Exception>();
        foreach (var component in _components.Reverse())
        {
            try
            {
                component.Stop();
                if (component.IsActive()) throw new InvalidOperationException("A protection listener remains active after stop.");
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Protection listener stop failed.");
                failures.Add(exception);
            }
        }
        if (failures.Count != 0) throw new AggregateException("Not all protection listeners stopped.", failures);
        _lastTransitionSucceeded = true;
    }

    /// <summary>Prevents healthy status after a lifecycle transition whose desired state could not be persisted.</summary>
    public void MarkPersistenceFailure() => _lastTransitionSucceeded = false;
}
