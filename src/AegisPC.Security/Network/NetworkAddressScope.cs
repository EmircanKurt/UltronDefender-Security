using System.Net;
using System.Net.Sockets;

namespace AegisPC.Security.Network;

/// <summary>Classifies address scope without interpreting a public address as malicious.</summary>
public static class NetworkAddressScope
{
    /// <summary>Recognizes private, loopback, link-local, multicast and unspecified addresses, including mapped IPv4.</summary>
    public static bool IsLocalOrPrivate(string? value)
    {
        if (!IPAddress.TryParse(value, out var address)) return true;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address)) return true;
        byte[] bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
            return bytes[0] is 0 or 10 or 127 or >= 224 ||
                (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                (bytes[0] == 192 && bytes[1] == 168) || (bytes[0] == 169 && bytes[1] == 254);
        return address.Equals(IPAddress.IPv6Any) || address.IsIPv6LinkLocal || address.IsIPv6Multicast ||
            (bytes[0] & 0xfe) == 0xfc;
    }
}
