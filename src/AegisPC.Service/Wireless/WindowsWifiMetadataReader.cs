using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using AegisPC.Contracts.Protection;

namespace AegisPC.Service.Wireless;

/// <summary>Passive local Wi-Fi metadata. It never scans networks or requests/bypasses Windows location consent.</summary>
internal static class WindowsWifiMetadataReader
{
    internal static (SecurityObservationAvailability Availability, WifiConnectionObservation[] Connections, string? Limitation)
        Capture(bool allowLocationDependentMetadata)
    {
        if (!allowLocationDependentMetadata)
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(item => item.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 && item.OperationalStatus == OperationalStatus.Up)
                .Take(32).Select(item => new WifiConnectionObservation
                { InterfaceId = Guid.TryParse(item.Id, out var id) ? id : Guid.Empty, Security = ObservedWifiSecurity.Unknown }).ToArray();
            return (SecurityObservationAvailability.Partial, interfaces,
                "Location-dependent Wi-Fi metadata is disabled; SSID/BSSID/security attributes are not verified.");
        }
        IntPtr client = IntPtr.Zero, list = IntPtr.Zero;
        try
        {
            uint open = WlanOpenHandle(2, IntPtr.Zero, out _, out client);
            if (open != 0 || client == IntPtr.Zero) return (SecurityObservationAvailability.Unavailable, [], "WLAN client is unavailable.");
            uint enumerate = WlanEnumInterfaces(client, IntPtr.Zero, out list);
            if (enumerate != 0 || list == IntPtr.Zero) return (SecurityObservationAvailability.Unavailable, [], "WLAN interface enumeration failed.");
            int count = Marshal.ReadInt32(list);
            if (count is < 0 or > 64) return (SecurityObservationAvailability.Partial, [], "WLAN interface metadata exceeded its bounded budget.");
            var connections = new List<WifiConnectionObservation>();
            bool complete = true;
            string? limitation = null;
            for (int index = 0; index < count; index++)
            {
                var item = Marshal.PtrToStructure<InterfaceInfo>(IntPtr.Add(list, 8 + index * Marshal.SizeOf<InterfaceInfo>()));
                if (item.State != 1) continue; // wlan_interface_state_connected
                IntPtr data = IntPtr.Zero;
                try
                {
                    var id = item.Id;
                    uint result = WlanQueryInterface(client, ref id, 7, IntPtr.Zero, out uint bytes, out data, out _);
                    if (result != 0 || data == IntPtr.Zero || bytes < Marshal.SizeOf<ConnectionAttributes>() || bytes > 1048576)
                    {
                        complete = false;
                        limitation = result == 5 ? "Windows denied location-dependent Wi-Fi metadata; no permission was requested or bypassed."
                            : "A connected Wi-Fi interface could not be queried.";
                        connections.Add(new() { InterfaceId = id, Security = ObservedWifiSecurity.Unknown });
                        continue;
                    }
                    var connection = Marshal.PtrToStructure<ConnectionAttributes>(data);
                    if (connection.Association.Ssid.Length > 32) { complete = false; continue; }
                    connections.Add(new()
                    {
                        InterfaceId = id,
                        Ssid = Encoding.UTF8.GetString(connection.Association.Ssid.Bytes, 0, (int)connection.Association.Ssid.Length),
                        Bssid = Convert.ToHexString(connection.Association.Bssid),
                        Security = WirelessProtectionPolicy.ClassifyWifiSecurity(connection.Security.SecurityEnabled != 0,
                            connection.Security.Authentication, connection.Security.Cipher)
                    });
                }
                finally { if (data != IntPtr.Zero) WlanFreeMemory(data); }
            }
            return (count == 0 ? SecurityObservationAvailability.Unavailable : complete ? SecurityObservationAvailability.Available :
                SecurityObservationAvailability.Partial, connections.ToArray(), count == 0 ? "No native WLAN interface was reported." : limitation);
        }
        finally
        {
            if (list != IntPtr.Zero) WlanFreeMemory(list);
            if (client != IntPtr.Zero) WlanCloseHandle(client, IntPtr.Zero);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct InterfaceInfo
    { public Guid Id; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Description; public int State; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Ssid { public uint Length; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Bytes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct AssociationAttributes
    {
        public Ssid Ssid;
        public int BssType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] Bssid;
        public int PhyType;
        public uint PhyIndex;
        public uint Quality;
        public uint RxRate;
        public uint TxRate;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    { public int SecurityEnabled; public int OneXEnabled; public uint Authentication; public uint Cipher; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ConnectionAttributes
    {
        public int State;
        public int Mode;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string ProfileName;
        public AssociationAttributes Association;
        public SecurityAttributes Security;
    }
    [DllImport("wlanapi.dll")]
    private static extern uint WlanOpenHandle(uint version, IntPtr reserved, out uint negotiatedVersion, out IntPtr handle);
    [DllImport("wlanapi.dll")]
    private static extern uint WlanEnumInterfaces(IntPtr handle, IntPtr reserved, out IntPtr interfaceList);
    [DllImport("wlanapi.dll")]
    private static extern uint WlanQueryInterface(IntPtr handle, ref Guid id, int opcode, IntPtr reserved,
        out uint size, out IntPtr data, out int valueType);
    [DllImport("wlanapi.dll")]
    private static extern uint WlanCloseHandle(IntPtr handle, IntPtr reserved);
    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr memory);
}
