using AegisPC.Core.Models.Devices;

namespace AegisPC.Contracts.Devices;

/// <summary>Service-owned device observation. No keyboard input, firmware operation or device disable is performed.</summary>
public interface IDeviceInventoryMonitor
{
    /// <summary>Whether the monitor's processing loop is active, independently of discovery completeness.</summary>
    bool IsRunning { get; }
    /// <summary>Latest immutable inventory, including discovery gaps and UTC age.</summary>
    DeviceInventorySnapshot CurrentSnapshot { get; }
    /// <summary>Raised after a new snapshot or lifecycle/discovery failure.</summary>
    event Action<DeviceInventorySnapshot>? SnapshotChanged;
    /// <summary>Registers notifications before enumeration; linked cancellation ends this generation.</summary>
    Task StartAsync(CancellationToken cancellationToken = default);
    /// <summary>Unregisters callbacks and cancels insertion jobs before detaching watchers.</summary>
    Task StopAsync(CancellationToken cancellationToken = default);
}
