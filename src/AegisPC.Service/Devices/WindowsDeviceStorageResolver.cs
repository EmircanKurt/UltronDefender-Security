using System.Runtime.InteropServices;
using System.Text;
using AegisPC.Contracts.Devices;
using AegisPC.Core.Models.Devices;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Devices;

/// <summary>Read-only Windows volume, physical disk and PnP association queries with bounded buffers.</summary>
public sealed class WindowsDeviceStorageResolver(ILogger<WindowsDeviceStorageResolver>? logger = null) : IDeviceStorageResolver
{
    /// <inheritdoc />
    public Task<DeviceInventorySnapshot> ResolveAsync(IReadOnlyList<DeviceMetadata> devices,
        bool deviceEnumerationComplete, string? deviceFailureReason, CancellationToken cancellationToken = default) =>
        Task.Run(() => Resolve(devices, deviceEnumerationComplete, deviceFailureReason, cancellationToken), cancellationToken);

    private DeviceInventorySnapshot Resolve(IReadOnlyList<DeviceMetadata> devices, bool deviceEnumerationComplete,
        string? deviceFailureReason, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            return new DeviceInventorySnapshot(devices, [], false, "Windows volume discovery is unavailable.");
        var volumes = new List<MediaVolumeMetadata>();
        var volumeName = new StringBuilder(1024);
        var search = WindowsStorageNative.FindFirstVolumeW(volumeName, (uint)volumeName.Capacity);
        if (search == new IntPtr(-1))
            return new DeviceInventorySnapshot(devices, volumes, false, "Volume enumeration could not start.");
        bool enumerated = false;
        try
        {
            for (int index = 0; index < 4096; index++)
            {
                ct.ThrowIfCancellationRequested();
                try { volumes.Add(ReadVolume(volumeName.ToString(), devices, ct)); }
                catch (OperationCanceledException) { throw; }
                catch (Exception exception)
                {
                    logger?.LogWarning(exception, "A present volume could not be queried.");
                    volumes.Add(new MediaVolumeMetadata { VolumeGuid = volumeName.ToString(),
                        Limitation = "Volume metadata query failed; content has not been inspected." });
                }
                volumeName.Clear();
                if (WindowsStorageNative.FindNextVolumeW(search, volumeName, (uint)volumeName.Capacity)) continue;
                enumerated = Marshal.GetLastWin32Error() == 18; // ERROR_NO_MORE_FILES, not SetupAPI's ERROR_NO_MORE_ITEMS.
                break;
            }
        }
        finally { WindowsStorageNative.FindVolumeClose(search); }
        bool membershipComplete = enumerated;
        bool complete = membershipComplete && deviceEnumerationComplete && devices.All(d => d.MetadataComplete) && volumes.All(v => v.Limitation == null);
        string? failure = complete ? null : deviceFailureReason ??
            (!enumerated ? "Volume enumeration failed or exceeded its budget." : "Some device or volume metadata is unavailable.");
        return new DeviceInventorySnapshot(devices, volumes, complete, failure, presenceComplete: membershipComplete);
    }

    private static MediaVolumeMetadata ReadVolume(string volumeGuid, IReadOnlyList<DeviceMetadata> devices, CancellationToken ct)
    {
        var mounts = ReadMountPaths(volumeGuid);
        var driveType = (DriveType)WindowsStorageNative.GetDriveTypeW(volumeGuid);
        bool ready = WindowsStorageNative.GetVolumeInformationW(volumeGuid, null, 0, out _, out _, out _, null, 0);
        ct.ThrowIfCancellationRequested();
        using var handle = WindowsStorageNative.OpenMetadata(volumeGuid.TrimEnd('\\'));
        var extents = new byte[8 + 128 * 24];
        IReadOnlyList<uint>? numbers = !handle.IsInvalid && WindowsStorageNative.DeviceIoControl(handle,
            WindowsStorageNative.GetVolumeExtents, null, 0, extents, (uint)extents.Length,
            out uint returned, IntPtr.Zero) ? DeviceDescriptorDecoder.ReadVolumeDiskNumbers(extents, checked((int)returned)) : null;
        uint? volumeBus = !handle.IsInvalid ? WindowsStorageNative.ReadBusType(handle) : null;
        ct.ThrowIfCancellationRequested();
        var disks = devices.Where(d => d.DiskNumber.HasValue && numbers?.Contains(d.DiskNumber.Value) == true).ToArray();
        uint? bus = volumeBus ?? disks.Select(d => d.StorageBusType).FirstOrDefault(v => v.HasValue);
        UsbAssociation usb = volumeBus == 7 || disks.Any(d => d.UsbAssociation == UsbAssociation.Usb)
            ? UsbAssociation.Usb : numbers is { Count: > 0 } && numbers.All(n =>
                disks.Any(d => d.DiskNumber == n && d.UsbAssociation == UsbAssociation.NotUsb))
                    ? UsbAssociation.NotUsb : UsbAssociation.Unknown;
        return new MediaVolumeMetadata
        {
            VolumeGuid = volumeGuid, MountPaths = mounts ?? [], DiskNumbers = numbers ?? [],
            DeviceInstanceIds = Array.AsReadOnly(disks.Select(d => d.InstanceId).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()),
            IsReady = ready, DriveType = driveType, StorageBusType = bus, UsbAssociation = usb,
            Limitation = !ready ? "File system is not ready; content has not been inspected." :
                mounts == null ? "Volume mount paths are unavailable." :
                numbers == null || usb == UsbAssociation.Unknown ? "Physical transport or volume association is unavailable." : null
        };
    }

    private static IReadOnlyList<string>? ReadMountPaths(string volumeGuid)
    {
        var buffer = new char[256];
        if (!WindowsStorageNative.GetVolumePathNamesForVolumeNameW(volumeGuid, buffer, (uint)buffer.Length, out uint required))
        {
            if (Marshal.GetLastWin32Error() != 234 || required <= buffer.Length || required > 32768) return null;
            buffer = new char[required];
            if (!WindowsStorageNative.GetVolumePathNamesForVolumeNameW(volumeGuid, buffer, (uint)buffer.Length, out required)) return null;
        }
        if (required > buffer.Length) return null;
        return Array.AsReadOnly(new string(buffer, 0, (int)required).Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }
}
