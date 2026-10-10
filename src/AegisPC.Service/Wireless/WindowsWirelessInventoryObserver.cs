using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using AegisPC.Contracts.Protection;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Wireless;

/// <summary>Inert passive WLAN/Classic Bluetooth adapter; location-dependent Wi-Fi queries are disabled by default.</summary>
public sealed class WindowsWirelessInventoryObserver(bool allowLocationDependentWifiMetadata = false,
    ILogger<WindowsWirelessInventoryObserver>? logger = null) : IWirelessInventoryObserver
{
    /// <inheritdoc />
    public WirelessInventorySnapshot Capture(DateTime utcNow)
    {
        if (!OperatingSystem.IsWindows()) return new()
        {
            CapturedAtUtc = utcNow, WifiAvailability = SecurityObservationAvailability.Unavailable,
            BluetoothAvailability = SecurityObservationAvailability.Unavailable,
            Limitations = ["Native wireless inventory requires Windows."]
        };
        var limitations = new List<string>
        {
            "ObservationOnly: radio, pairing and network settings are not changed.",
            "Classic Bluetooth remembered/connected metadata does not cover BLE traffic, pairing interception or firmware security.",
            "Reported SSID, BSSID and Bluetooth addresses can be spoofed; metadata is not proof of device authenticity."
        };
        var wifi = (Availability: SecurityObservationAvailability.Unavailable, Connections: Array.Empty<WifiConnectionObservation>());
        var bluetooth = (Availability: SecurityObservationAvailability.Unavailable, Devices: Array.Empty<BluetoothDeviceObservation>());
        try
        {
            var captured = WindowsWifiMetadataReader.Capture(allowLocationDependentWifiMetadata);
            wifi = (captured.Availability, captured.Connections);
            if (captured.Limitation != null) limitations.Add(captured.Limitation);
        }
        catch (Exception exception) when (exception is ExternalException or DllNotFoundException or EntryPointNotFoundException or
            InvalidOperationException or ArgumentException or NetworkInformationException or UnauthorizedAccessException)
        {
            logger?.LogWarning(exception, "Passive Wi-Fi metadata capture failed; current security attributes are unknown.");
            limitations.Add("Passive Wi-Fi metadata failed or was denied.");
        }
        try
        {
            var captured = WindowsBluetoothMetadataReader.Capture();
            bluetooth = (captured.Availability, captured.Devices);
            if (captured.Limitation != null) limitations.Add(captured.Limitation);
        }
        catch (Exception exception) when (exception is ExternalException or DllNotFoundException or EntryPointNotFoundException or
            InvalidOperationException or ArgumentException or UnauthorizedAccessException)
        {
            logger?.LogWarning(exception, "Passive Classic Bluetooth capture failed; availability is unknown.");
            limitations.Add("Passive Classic Bluetooth metadata failed or was denied.");
        }
        return new()
        {
            CapturedAtUtc = utcNow, WifiAvailability = wifi.Availability, BluetoothAvailability = bluetooth.Availability,
            WifiConnections = wifi.Connections, BluetoothDevices = bluetooth.Devices, Limitations = limitations.ToArray()
        };
    }
}
