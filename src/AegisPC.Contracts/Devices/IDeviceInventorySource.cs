using AegisPC.Core.Models.Devices;

namespace AegisPC.Contracts.Devices;

/// <summary>Read-only OS adapter, replaceable with inert fixtures for lifecycle tests.</summary>
public interface IDeviceInventorySource
{
    /// <summary>Registers callbacks without enumerating; returned handle must be disposed outside the callback.</summary>
    IDisposable Subscribe(Action<DeviceDiscoverySignal> onSignal);
    /// <summary>Captures bounded present interface and volume metadata; partial queries must remain visible.</summary>
    Task<DeviceInventorySnapshot> CaptureAsync(CancellationToken cancellationToken = default);
}

/// <summary>Maps current physical disk interfaces to volume GUIDs and mount paths without scanning their contents.</summary>
public interface IDeviceStorageResolver
{
    /// <summary>Returns volume discovery and its completeness; device IDs are descriptors, never trust.</summary>
    Task<DeviceInventorySnapshot> ResolveAsync(IReadOnlyList<DeviceMetadata> devices,
        bool deviceEnumerationComplete, string? deviceFailureReason, CancellationToken cancellationToken = default);
}
