using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Service.Devices;

/// <summary>Metadata-only storage queries; no media write or firmware control codes are exposed.</summary>
internal static class WindowsStorageNative
{
    // CTL_CODE values verified against Microsoft's ntddstor.h and winioctl.h.
    internal const uint QueryProperty = (0x2du << 16) | (0x500u << 2);
    internal const uint GetDeviceNumber = (0x2du << 16) | (0x420u << 2);
    internal const uint GetVolumeExtents = 0x56u << 16;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeFileHandle CreateFileW(string path, uint desiredAccess, uint shareMode,
        IntPtr security, uint creationDisposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeviceIoControl(SafeFileHandle handle, uint code, byte[]? input, uint inputBytes,
        byte[] output, uint outputBytes, out uint returnedBytes, IntPtr overlapped);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr FindFirstVolumeW(StringBuilder volume, uint characters);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FindNextVolumeW(IntPtr enumeration, StringBuilder volume, uint characters);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FindVolumeClose(IntPtr enumeration);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetVolumePathNamesForVolumeNameW(string volume, char[] paths, uint characters,
        out uint requiredCharacters);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetVolumeInformationW(string root, StringBuilder? label, uint labelCharacters,
        out uint serial, out uint maximumComponent, out uint flags, StringBuilder? fileSystem, uint fileSystemCharacters);

    internal static SafeFileHandle OpenMetadata(string path) => CreateFileW(path, 0, 1 | 2 | 4,
        IntPtr.Zero, 3, 0, IntPtr.Zero);

    internal static uint? ReadDiskNumber(SafeFileHandle handle)
    {
        var output = new byte[12];
        return DeviceIoControl(handle, GetDeviceNumber, null, 0, output, 12, out var count, IntPtr.Zero) && count >= 12
            ? BitConverter.ToUInt32(output, 4) : null;
    }

    internal static uint? ReadBusType(SafeFileHandle handle)
    {
        var query = new byte[12]; // StorageDeviceProperty=0, PropertyStandardQuery=0.
        var header = new byte[8];
        if (!DeviceIoControl(handle, QueryProperty, query, 12, header, 8, out var count, IntPtr.Zero) || count < 8)
            return null;
        uint size = BitConverter.ToUInt32(header, 4);
        if (size < 36 || size > WindowsDeviceNative.MaximumBufferBytes) return null;
        var descriptor = new byte[size];
        if (!DeviceIoControl(handle, QueryProperty, query, 12, descriptor, size, out count, IntPtr.Zero)) return null;
        return DeviceDescriptorDecoder.ReadStorageBusType(descriptor, (int)Math.Min(count, size));
    }
}
