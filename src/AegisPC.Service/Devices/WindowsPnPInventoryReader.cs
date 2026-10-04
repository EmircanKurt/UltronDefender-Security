using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using AegisPC.Core.Models.Devices;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Devices;

/// <summary>Enumerates disk/HID interface metadata with bounded property buffers and parent depth.</summary>
internal sealed class WindowsPnPInventoryReader(ILogger? logger)
{
    private static readonly Guid DeviceProperties = new("a45c254e-df1c-4efd-8020-67d146a850e0");
    private static readonly Guid ContainerProperties = new("8c7ed206-3f8a-4827-b3ab-ae9e1faefc6c");

    internal (IReadOnlyList<DeviceMetadata> Devices, bool Complete) Enumerate(CancellationToken cancellationToken)
    {
        var result = new List<DeviceMetadata>();
        bool complete = true;
        foreach (var interfaceClass in new[] { WindowsDeviceNative.DiskInterface, WindowsDeviceNative.HidInterface })
        {
            cancellationToken.ThrowIfCancellationRequested();
            var classGuid = interfaceClass;
            var set = WindowsDeviceNative.SetupDiGetClassDevsW(ref classGuid, null, IntPtr.Zero, 2 | 16);
            if (set == new IntPtr(-1))
            {
                complete = false;
                logger?.LogWarning("Device interface enumeration could not open class {Class}: {Error}", classGuid, Marshal.GetLastWin32Error());
                continue;
            }
            try { complete &= ReadInterfaces(set, classGuid, result, cancellationToken); }
            finally
            {
                if (!WindowsDeviceNative.SetupDiDestroyDeviceInfoList(set))
                    logger?.LogWarning("Device information set cleanup failed: {Error}", Marshal.GetLastWin32Error());
            }
        }
        return (Array.AsReadOnly(result.ToArray()), complete);
    }

    private bool ReadInterfaces(IntPtr set, Guid classGuid, List<DeviceMetadata> results, CancellationToken ct)
    {
        bool complete = true;
        const uint maximumInterfaces = 4096;
        for (uint index = 0; index < maximumInterfaces; index++)
        {
            ct.ThrowIfCancellationRequested();
            var data = new WindowsDeviceNative.InterfaceData { Size = (uint)Marshal.SizeOf<WindowsDeviceNative.InterfaceData>() };
            if (!WindowsDeviceNative.SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref classGuid, index, ref data))
            {
                int error = Marshal.GetLastWin32Error();
                if (error != WindowsDeviceNative.NoMoreItems)
                    logger?.LogWarning("Device interface enumeration stopped with error {Error}", error);
                return complete && error == WindowsDeviceNative.NoMoreItems;
            }
            try
            {
                var metadata = ReadInterface(set, ref data, classGuid);
                results.Add(metadata);
            }
            catch (Exception exception)
            {
                complete = false;
                logger?.LogWarning(exception, "A present device interface could not be queried.");
            }
        }
        logger?.LogWarning("Device interface enumeration reached the bounded interface budget.");
        return false;
    }

    private DeviceMetadata ReadInterface(IntPtr set, ref WindowsDeviceNative.InterfaceData data, Guid classGuid)
    {
        var info = new WindowsDeviceNative.DeviceInfoData { Size = (uint)Marshal.SizeOf<WindowsDeviceNative.DeviceInfoData>() };
        WindowsDeviceNative.SetupDiGetDeviceInterfaceDetailW(set, ref data, IntPtr.Zero, 0, out uint needed, ref info);
        if (needed < 8 || needed > WindowsDeviceNative.MaximumBufferBytes)
            throw new InvalidDataException("Device interface detail exceeded its buffer budget.");
        var buffer = Marshal.AllocHGlobal((int)needed);
        string path;
        try
        {
            Marshal.WriteInt32(buffer, IntPtr.Size == 8 ? 8 : 6);
            if (!WindowsDeviceNative.SetupDiGetDeviceInterfaceDetailW(set, ref data, buffer, needed, out uint returned, ref info) || returned > needed)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Device interface detail is unavailable.");
            path = Marshal.PtrToStringUni(buffer + 4, (int)(needed - 4) / 2)?.Split('\0')[0] ?? string.Empty;
        }
        finally { Marshal.FreeHGlobal(buffer); }
        string identity = ReadDeviceId(info.DevInst);
        var ancestry = ReadAncestors(info.DevInst);
        using var handle = WindowsStorageNative.OpenMetadata(path);
        bool disk = classGuid == WindowsDeviceNative.DiskInterface;
        uint? number = disk && !handle.IsInvalid ? WindowsStorageNative.ReadDiskNumber(handle) : null;
        uint? bus = disk && !handle.IsInvalid ? WindowsStorageNative.ReadBusType(handle) : null;
        var usages = !disk && !handle.IsInvalid ? ReadHidUsages(handle) : (Page: (ushort?)null, Usage: (ushort?)null);
        DeviceFunction function = disk ? DeviceFunction.Storage : DeviceFunction.Hid;
        if (usages.Page == 1 && usages.Usage == 6) function |= DeviceFunction.Keyboard;
        if (usages.Page == 1 && usages.Usage == 2) function |= DeviceFunction.Mouse;
        bool queried = !string.IsNullOrEmpty(identity) && ancestry.Complete &&
            (disk ? number.HasValue && bus.HasValue : usages.Page.HasValue);
        return new DeviceMetadata
        {
            InstanceId = identity, InterfacePath = path, InterfaceClassGuid = classGuid,
            ClassGuid = ReadGuid(info.DevInst, new WindowsDeviceNative.PropertyKey(DeviceProperties, 10)),
            ContainerId = ReadGuid(info.DevInst, new WindowsDeviceNative.PropertyKey(ContainerProperties, 2)),
            DisplayName = ReadString(info.DevInst, 14) ?? ReadString(info.DevInst, 2) ?? string.Empty,
            ParentInstanceId = ancestry.Ids.FirstOrDefault(), AncestorInstanceIds = Array.AsReadOnly(ancestry.Ids.ToArray()),
            Functions = function, HidUsagePage = usages.Page, HidUsage = usages.Usage,
            DiskNumber = number, StorageBusType = bus,
            UsbAssociation = DeviceDescriptorDecoder.ClassifyUsb(bus, ancestry.Usb, ancestry.Complete),
            MetadataComplete = queried, Limitation = queried ? null : "Device identity, transport or HID capability query is incomplete."
        };
    }

    private (List<string> Ids, bool Usb, bool Complete) ReadAncestors(uint devInst)
    {
        var identities = new List<string>();
        var visited = new HashSet<uint>();
        bool usb = false;
        bool propertiesComplete = true;
        for (int depth = 0; depth < 32; depth++)
        {
            if (!visited.Add(devInst)) return (identities, usb, false);
            string? enumerator = ReadString(devInst, 24);
            propertiesComplete &= enumerator != null;
            usb |= string.Equals(enumerator, "USB", StringComparison.OrdinalIgnoreCase);
            uint result = WindowsDeviceNative.CM_Get_Parent(out uint parent, devInst, 0);
            if (result != 0) return (identities, usb, propertiesComplete && result == 0x0d); // CR_NO_SUCH_DEVNODE at the root.
            string id = ReadDeviceId(parent);
            if (string.IsNullOrEmpty(id)) return (identities, usb, false);
            identities.Add(id);
            devInst = parent;
        }
        return (identities, usb, false);
    }

    private static string ReadDeviceId(uint devInst)
    {
        var buffer = new StringBuilder(200);
        return WindowsDeviceNative.CM_Get_Device_IDW(devInst, buffer, (uint)buffer.Capacity, 0) == 0
            ? buffer.ToString() : string.Empty;
    }

    private static byte[]? ReadProperty(uint devInst, WindowsDeviceNative.PropertyKey key, out uint type)
    {
        uint size = 0;
        WindowsDeviceNative.CM_Get_DevNode_PropertyW(devInst, ref key, out type, null, ref size, 0);
        if (size == 0 || size > WindowsDeviceNative.MaximumBufferBytes) return null;
        var buffer = new byte[size];
        if (WindowsDeviceNative.CM_Get_DevNode_PropertyW(devInst, ref key, out type, buffer, ref size, 0) != 0 || size > buffer.Length)
            return null;
        return buffer.AsSpan(0, (int)size).ToArray();
    }

    private static string? ReadString(uint devInst, uint property)
    {
        var data = ReadProperty(devInst, new WindowsDeviceNative.PropertyKey(DeviceProperties, property), out uint type);
        return data == null || type != 0x12 || data.Length % 2 != 0 ? null : Encoding.Unicode.GetString(data).TrimEnd('\0');
    }

    private static Guid? ReadGuid(uint devInst, WindowsDeviceNative.PropertyKey key)
    {
        var data = ReadProperty(devInst, key, out uint type);
        return data is { Length: 16 } && type == 0x0d ? new Guid(data) : null;
    }

    private static (ushort? Page, ushort? Usage) ReadHidUsages(Microsoft.Win32.SafeHandles.SafeFileHandle handle)
    {
        if (!WindowsDeviceNative.HidD_GetPreparsedData(handle, out var data)) return (null, null);
        var caps = Marshal.AllocHGlobal(64); // sizeof(HIDP_CAPS), no input report is ever requested.
        try
        {
            if (WindowsDeviceNative.HidP_GetCaps(data, caps) != 0x00110000) return (null, null);
            return ((ushort)Marshal.ReadInt16(caps, 2), (ushort)Marshal.ReadInt16(caps));
        }
        finally { Marshal.FreeHGlobal(caps); WindowsDeviceNative.HidD_FreePreparsedData(data); }
    }
}
