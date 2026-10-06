using System.Runtime.InteropServices;
using AegisPC.Contracts.Protection;

namespace AegisPC.Service.Wireless;

/// <summary>Bounded passive Classic Bluetooth inventory. It never issues discovery inquiry, pairing or radio changes.</summary>
internal static class WindowsBluetoothMetadataReader
{
    internal static (SecurityObservationAvailability Availability, BluetoothDeviceObservation[] Devices, string? Limitation) Capture()
    {
        var radioParameters = new FindRadioParameters { Size = (uint)Marshal.SizeOf<FindRadioParameters>() };
        IntPtr search = BluetoothFindFirstRadio(ref radioParameters, out var radio);
        if (search == IntPtr.Zero)
            return (SecurityObservationAvailability.Unavailable, [], "No Classic Bluetooth radio could be enumerated.");
        var devices = new Dictionary<string, BluetoothDeviceObservation>(StringComparer.Ordinal);
        bool complete = true;
        try
        {
            for (int count = 0; count < 32; count++)
            {
                try { complete &= ReadDevices(radio, devices); }
                finally { if (radio != IntPtr.Zero) CloseHandle(radio); radio = IntPtr.Zero; }
                if (devices.Count >= 256) { complete = false; break; }
                if (!BluetoothFindNextRadio(search, out radio))
                { if (Marshal.GetLastWin32Error() != 259) complete = false; break; }
                if (count == 31) complete = false;
            }
        }
        finally
        {
            if (radio != IntPtr.Zero) CloseHandle(radio);
            BluetoothFindRadioClose(search);
        }
        return (complete ? SecurityObservationAvailability.Available : SecurityObservationAvailability.Partial,
            devices.Values.ToArray(), complete ? null : "Classic Bluetooth metadata exceeded its budget or a native query failed.");
    }

    private static bool ReadDevices(IntPtr radio, Dictionary<string, BluetoothDeviceObservation> devices)
    {
        var parameters = new SearchParameters
        {
            Size = (uint)Marshal.SizeOf<SearchParameters>(), ReturnAuthenticated = true, ReturnRemembered = true,
            ReturnConnected = true, ReturnUnknown = false, IssueInquiry = false, Radio = radio
        };
        var info = new DeviceInfo { Size = (uint)Marshal.SizeOf<DeviceInfo>() };
        IntPtr search = BluetoothFindFirstDevice(ref parameters, ref info);
        if (search == IntPtr.Zero) return Marshal.GetLastWin32Error() == 259;
        try
        {
            for (int records = 0; records < 512 && devices.Count < 256; records++)
            {
                string identity = (info.Address & 0x0000FFFFFFFFFFFFUL).ToString("X12", System.Globalization.CultureInfo.InvariantCulture);
                devices[identity] = new()
                {
                    Address = identity, DisplayName = info.Name ?? string.Empty, Connected = info.Connected,
                    Remembered = info.Remembered, Authenticated = info.Authenticated
                };
                info.Size = (uint)Marshal.SizeOf<DeviceInfo>();
                if (!BluetoothFindNextDevice(search, ref info)) return Marshal.GetLastWin32Error() == 259;
            }
            return false;
        }
        finally { BluetoothFindDeviceClose(search); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FindRadioParameters { public uint Size; }
    [StructLayout(LayoutKind.Sequential)]
    private struct SearchParameters
    {
        public uint Size;
        [MarshalAs(UnmanagedType.Bool)] public bool ReturnAuthenticated;
        [MarshalAs(UnmanagedType.Bool)] public bool ReturnRemembered;
        [MarshalAs(UnmanagedType.Bool)] public bool ReturnUnknown;
        [MarshalAs(UnmanagedType.Bool)] public bool ReturnConnected;
        [MarshalAs(UnmanagedType.Bool)] public bool IssueInquiry;
        public byte TimeoutMultiplier;
        public IntPtr Radio;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SystemTime
    { public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DeviceInfo
    {
        public uint Size;
        public ulong Address;
        public uint ClassOfDevice;
        [MarshalAs(UnmanagedType.Bool)] public bool Connected;
        [MarshalAs(UnmanagedType.Bool)] public bool Remembered;
        [MarshalAs(UnmanagedType.Bool)] public bool Authenticated;
        public SystemTime LastSeen;
        public SystemTime LastUsed;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 248)] public string? Name;
    }
    [DllImport("bthprops.cpl", SetLastError = true)]
    private static extern IntPtr BluetoothFindFirstRadio(ref FindRadioParameters parameters, out IntPtr radio);
    [DllImport("bthprops.cpl", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BluetoothFindNextRadio(IntPtr search, out IntPtr radio);
    [DllImport("bthprops.cpl")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BluetoothFindRadioClose(IntPtr search);
    [DllImport("bthprops.cpl", SetLastError = true)]
    private static extern IntPtr BluetoothFindFirstDevice(ref SearchParameters parameters, ref DeviceInfo info);
    [DllImport("bthprops.cpl", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BluetoothFindNextDevice(IntPtr search, ref DeviceInfo info);
    [DllImport("bthprops.cpl")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BluetoothFindDeviceClose(IntPtr search);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
