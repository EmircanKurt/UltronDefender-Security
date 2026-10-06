using AegisPC.Contracts.Protection;

namespace AegisPC.Service.Wireless;

/// <summary>Bounded passive metadata review. Configuration changes never authorize radio/network changes or malware actions.</summary>
public sealed class WirelessProtectionPolicy
{
    private readonly Dictionary<Guid, WifiConnectionObservation> _wifiBaseline = new();
    private readonly HashSet<string> _bluetoothBaseline = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private bool _bluetoothInitialized;

    /// <summary>Classifies documented DOT11 authentication/cipher constants without treating unknown/OWE algorithms as authenticated WPA.</summary>
    public static ObservedWifiSecurity ClassifyWifiSecurity(bool enabled, uint authentication, uint cipher)
    {
        // Documented values: https://learn.microsoft.com/windows/win32/nativewifi/dot11-auth-algorithm
        // and https://learn.microsoft.com/windows/win32/nativewifi/dot11-cipher-algorithm .
        if (!enabled || cipher == 0) return ObservedWifiSecurity.Open;
        if (cipher is 1 or 2 or 5 or 0x101 || authentication is 2 or 3 or 4 or 5) return ObservedWifiSecurity.Legacy;
        if (cipher is not (4 or 8 or 9 or 10)) return ObservedWifiSecurity.Unknown;
        return authentication switch
        {
            6 or 7 => ObservedWifiSecurity.Wpa2,
            8 or 9 or 11 => ObservedWifiSecurity.Wpa3,
            _ => ObservedWifiSecurity.Unknown
        };
    }

    /// <summary>Reviews fresh bounded inventory and reports weak configurations/changes without establishing maliciousness.</summary>
    public WirelessProtectionSnapshot Evaluate(DateTime utcNow, WirelessInventorySnapshot inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        lock (_gate)
        {
            if (utcNow == default || utcNow.Kind != DateTimeKind.Utc || inventory.CapturedAtUtc == default ||
                inventory.CapturedAtUtc.Kind != DateTimeKind.Utc || inventory.CapturedAtUtc > utcNow ||
                utcNow - inventory.CapturedAtUtc > TimeSpan.FromSeconds(15))
                return new()
                {
                    Inventory = inventory with { WifiAvailability = SecurityObservationAvailability.Unavailable,
                        BluetoothAvailability = SecurityObservationAvailability.Unavailable, WifiConnections = [], BluetoothDevices = [],
                        Limitations = ["Wireless metadata is stale, absent, non-UTC or future-dated; no current security state is inferred."] }
                };
            var signals = new List<WirelessReviewSignal>();
            if (inventory.WifiAvailability is SecurityObservationAvailability.Available or SecurityObservationAvailability.Partial)
                foreach (var connection in (inventory.WifiConnections ?? []).Take(32))
                    if (connection != null) ReviewWifi(connection, signals);
            if (inventory.BluetoothAvailability is SecurityObservationAvailability.Available or SecurityObservationAvailability.Partial)
                foreach (var device in (inventory.BluetoothDevices ?? []).Take(256))
                    if (device != null && !string.IsNullOrWhiteSpace(device.Address) && device.Address.Length <= 64)
                    {
                        if (_bluetoothInitialized && !_bluetoothBaseline.Contains(device.Address))
                            signals.Add(new() { RuleId = "NewRememberedBluetoothDevice", SubjectIdentity = device.Address,
                                Explanation = "A new remembered/connected Classic Bluetooth device was reported. This is not proof of malicious hardware." });
                        if (_bluetoothBaseline.Count < 512) _bluetoothBaseline.Add(device.Address);
                    }
            if (inventory.BluetoothAvailability == SecurityObservationAvailability.Available) _bluetoothInitialized = true;
            bool exceeded = (inventory.WifiConnections?.Count ?? 0) > 32 || (inventory.BluetoothDevices?.Count ?? 0) > 256 ||
                _wifiBaseline.Count >= 64 || _bluetoothBaseline.Count >= 512;
            var limited = exceeded ? inventory with
            {
                WifiConnections = (inventory.WifiConnections ?? []).Take(32).ToArray(),
                BluetoothDevices = (inventory.BluetoothDevices ?? []).Take(256).ToArray(),
                Limitations = (inventory.Limitations ?? []).Append("Wireless metadata/history budget was reached; review coverage is incomplete.")
                    .Distinct().Take(16).ToArray()
            } : inventory;
            return new() { Inventory = limited, ReviewSignals = signals.Take(64).ToArray() };
        }
    }

    private void ReviewWifi(WifiConnectionObservation connection, List<WirelessReviewSignal> signals)
    {
        string identity = connection.InterfaceId.ToString("D");
        if (connection.Security is ObservedWifiSecurity.Open or ObservedWifiSecurity.Legacy)
            signals.Add(new() { RuleId = "WeakWifiConfiguration", SubjectIdentity = identity,
                Explanation = "The provider reports open or obsolete Wi-Fi security. Review the connection; an attack has not been established." });
        if (connection.InterfaceId == Guid.Empty || connection.Security == ObservedWifiSecurity.Unknown) return;
        if (_wifiBaseline.TryGetValue(connection.InterfaceId, out var previous))
        {
            if (connection.Ssid == previous.Ssid && SecurityRank(connection.Security) < SecurityRank(previous.Security))
                signals.Add(new() { RuleId = "WifiSecurityChanged", SubjectIdentity = identity,
                    Explanation = "The same reported network name now has weaker authentication/cipher metadata. SSIDs are spoofable; review is required." });
            if (connection.Ssid == previous.Ssid && previous.Bssid != null && connection.Bssid != null && previous.Bssid != connection.Bssid)
                signals.Add(new() { RuleId = "ReportedAccessPointChanged", SubjectIdentity = identity,
                    Explanation = "The reported access point address changed. Roaming/mesh can cause this; it is not proof of an evil-twin attack." });
        }
        if (_wifiBaseline.ContainsKey(connection.InterfaceId) || _wifiBaseline.Count < 64) _wifiBaseline[connection.InterfaceId] = connection;
    }

    private static int SecurityRank(ObservedWifiSecurity security) => security switch
    { ObservedWifiSecurity.Wpa3 => 3, ObservedWifiSecurity.Wpa2 => 2, ObservedWifiSecurity.Legacy => 1, _ => 0 };
}

/// <summary>Cached passive wireless review suitable for service sampling; construction does not touch native radios.</summary>
public sealed class WirelessProtectionMonitor(IWirelessInventoryObserver observer, WirelessProtectionPolicy policy) : IWirelessProtectionMonitor
{
    private WirelessProtectionSnapshot _snapshot = new()
    {
        Inventory = new() { Limitations = ["Wireless observation has not started.", "No radio or network enforcement is implemented."] }
    };

    /// <inheritdoc />
    public WirelessProtectionSnapshot CurrentSnapshot => Volatile.Read(ref _snapshot);

    /// <inheritdoc />
    public WirelessProtectionSnapshot Refresh(DateTime utcNow)
    {
        var next = policy.Evaluate(utcNow, observer.Capture(utcNow));
        Volatile.Write(ref _snapshot, next);
        return next;
    }
}
