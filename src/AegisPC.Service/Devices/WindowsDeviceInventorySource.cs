using AegisPC.Contracts.Devices;
using AegisPC.Core.Models.Devices;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Devices;

/// <summary>Windows disk/HID inventory adapter. Construction is inert; only Subscribe registers native callbacks.</summary>
public sealed class WindowsDeviceInventorySource : IDeviceInventorySource
{
    private readonly IDeviceStorageResolver _storage;
    private readonly ILogger<WindowsDeviceInventorySource>? _logger;

    /// <summary>Creates an adapter without opening devices or subscribing to OS events.</summary>
    public WindowsDeviceInventorySource(IDeviceStorageResolver storage, ILogger<WindowsDeviceInventorySource>? logger = null)
    { _storage = storage; _logger = logger; }

    /// <summary>Registers disk/HID interface callbacks; throws on a partial registration after cleaning acquired handles.</summary>
    public IDisposable Subscribe(Action<DeviceDiscoverySignal> onSignal)
    {
        ArgumentNullException.ThrowIfNull(onSignal);
        if (!OperatingSystem.IsWindowsVersionAtLeast(6, 2)) throw new PlatformNotSupportedException("PnP discovery requires Windows 8 or later.");
        return new NativeDeviceNotificationRegistration(onSignal, _logger);
    }

    /// <summary>Reads metadata on a background task; unsupported or failed queries return a partial snapshot.</summary>
    public async Task<DeviceInventorySnapshot> CaptureAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return new DeviceInventorySnapshot([], [], false, "Native device discovery requires Windows.");
        try
        {
            var inventory = await Task.Run(() => new WindowsPnPInventoryReader(_logger).Enumerate(cancellationToken), cancellationToken);
            return await _storage.ResolveAsync(inventory.Devices, inventory.Complete,
                inventory.Complete ? null : "Some present disk/HID descriptors could not be queried.", cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            _logger?.LogWarning(exception, "Native device inventory capture failed.");
            return new DeviceInventorySnapshot([], [], false, "Native device inventory capture failed: " + exception.GetType().Name);
        }
    }
}
