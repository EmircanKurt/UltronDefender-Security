namespace AegisPC.Service.Devices;

/// <summary>Bounded observation and readiness budgets; never changes OS device policies.</summary>
public sealed record DeviceInventoryMonitorOptions
{
    /// <summary>Maximum queued native signals before a visible gap is recorded.</summary>
    public int SignalCapacity { get; init; } = 64;
    /// <summary>Maximum concurrently attached media generations.</summary>
    public int MaximumActiveVolumes { get; init; } = 32;
    /// <summary>Periodic present-device reconciliation, including recovery from missed signals.</summary>
    public TimeSpan ReconcileInterval { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Successive waits giving startup attempts at elapsed 0, 1, 2, 4, 8 and 15 seconds, then normal reconciliation.</summary>
    public IReadOnlyList<TimeSpan> ReadinessRetryDelays { get; init; } = Array.AsReadOnly(new[]
    { TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(7) });
    /// <summary>Maximum wait for a cooperative media callback to finish during removal.</summary>
    public TimeSpan CallbackStopTimeout { get; init; } = TimeSpan.FromSeconds(5);

    internal void Validate()
    {
        if (SignalCapacity is < 1 or > 4096 || MaximumActiveVolumes is < 1 or > 256 ||
            ReadinessRetryDelays.Count > 100 || ReadinessRetryDelays.Any(delay => delay <= TimeSpan.Zero) ||
            ReconcileInterval <= TimeSpan.Zero || CallbackStopTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(DeviceInventoryMonitorOptions), "Device monitor budgets must be positive and bounded.");
    }
}
