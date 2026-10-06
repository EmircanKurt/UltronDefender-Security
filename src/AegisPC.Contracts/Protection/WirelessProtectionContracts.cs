namespace AegisPC.Contracts.Protection;

/// <summary>Native connection security classification; unknown and unsupported algorithms never imply secure Wi-Fi.</summary>
public enum ObservedWifiSecurity
{
    /// <summary>Security attributes were not available or the algorithm is unsupported.</summary>
    Unknown,
    /// <summary>The provider reports an open or unencrypted connection.</summary>
    Open,
    /// <summary>The provider reports obsolete WEP/TKIP or legacy WPA security.</summary>
    Legacy,
    /// <summary>The provider reports RSNA/WPA2 with a non-legacy cipher; AP authenticity is not proven.</summary>
    Wpa2,
    /// <summary>The provider reports a recognized WPA3 algorithm; AP authenticity is not proven.</summary>
    Wpa3
}

/// <summary>Passive metadata for a currently connected local wireless interface; no network scan or traffic inspection.</summary>
public sealed record WifiConnectionObservation
{
    /// <summary>Native interface GUID used for correlation rather than the user-visible connection name.</summary>
    public Guid InterfaceId { get; init; }
    /// <summary>Reported SSID for local display; an SSID is spoofable and not an authentication identity.</summary>
    public string Ssid { get; init; } = string.Empty;
    /// <summary>Current BSSID when permitted; roaming or a changed MAC does not establish an attack.</summary>
    public string? Bssid { get; init; }
    /// <summary>Provider-reported authentication/cipher classification, not a malware verdict.</summary>
    public ObservedWifiSecurity Security { get; init; }
}

/// <summary>Passive metadata for a remembered/connected Bluetooth device; discovery inquiry and auto-pairing are forbidden.</summary>
public sealed record BluetoothDeviceObservation
{
    /// <summary>Radio-reported device address for local change correlation; not a trustworthy firmware identity.</summary>
    public string Address { get; init; } = string.Empty;
    /// <summary>Radio-reported friendly name for local display only; it is not a trust decision.</summary>
    public string DisplayName { get; init; } = string.Empty;
    /// <summary>Whether the native provider reports the device connected.</summary>
    public bool Connected { get; init; }
    /// <summary>Whether the native provider reports the device remembered.</summary>
    public bool Remembered { get; init; }
    /// <summary>Whether the native provider reports authenticated pairing; this does not prove secure firmware.</summary>
    public bool Authenticated { get; init; }
}

/// <summary>Separate Wi-Fi and classic Bluetooth observer health with passive, bounded local metadata.</summary>
public sealed record WirelessInventorySnapshot
{
    /// <summary>UTC capture time; callers must reject stale/future metadata as evidence of current availability.</summary>
    public DateTime CapturedAtUtc { get; init; }
    /// <summary>Actual Wi-Fi metadata availability, including privacy permission failures.</summary>
    public SecurityObservationAvailability WifiAvailability { get; init; }
    /// <summary>Actual classic Bluetooth inventory availability; BLE/security hooks are not implied.</summary>
    public SecurityObservationAvailability BluetoothAvailability { get; init; }
    /// <summary>Bounded connected Wi-Fi metadata; empty does not prove there is no adapter.</summary>
    public IReadOnlyList<WifiConnectionObservation> WifiConnections { get; init; } = [];
    /// <summary>Bounded classic Bluetooth remembered/connected device metadata.</summary>
    public IReadOnlyList<BluetoothDeviceObservation> BluetoothDevices { get; init; } = [];
    /// <summary>Bounded metadata-source limitations without traffic, passwords or key material.</summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];
}

/// <summary>Passive native wireless inventory; construction must be inert and capture must not pair or change settings.</summary>
public interface IWirelessInventoryObserver
{
    /// <summary>Captures bounded metadata; precise-location permission is never requested or bypassed by the service.</summary>
    WirelessInventorySnapshot Capture(DateTime utcNow);
}

/// <summary>An explainable configuration/change signal, not proof of rogue AP, malware or insecure firmware.</summary>
public sealed record WirelessReviewSignal
{
    /// <summary>Stable rule ID used for deduplication; display names never establish a trust decision.</summary>
    public string RuleId { get; init; } = string.Empty;
    /// <summary>Local interface GUID or Bluetooth address involved in this metadata change.</summary>
    public string SubjectIdentity { get; init; } = string.Empty;
    /// <summary>Safe explanation that does not claim an attack has been confirmed.</summary>
    public string Explanation { get; init; } = string.Empty;
}

/// <summary>Passive inventory and bounded review signals; no radio/network disabling or pairing control is implemented.</summary>
public sealed record WirelessProtectionSnapshot
{
    /// <summary>Actual source metadata and capability coverage.</summary>
    public WirelessInventorySnapshot Inventory { get; init; } = new();
    /// <summary>Metadata/configuration changes requiring review; none authorize automatic blocking.</summary>
    public IReadOnlyList<WirelessReviewSignal> ReviewSignals { get; init; } = [];
    /// <summary>Always false for this read-only foundation.</summary>
    public bool NativeEnforcementActive => false;
}

/// <summary>Service-owned passive Wi-Fi/classic Bluetooth review, without network or radio policy changes.</summary>
public interface IWirelessProtectionMonitor
{
    /// <summary>Last passive observation or an explicitly pending snapshot.</summary>
    WirelessProtectionSnapshot CurrentSnapshot { get; }
    /// <summary>Captures read-only metadata and computes review signals without altering Windows settings.</summary>
    WirelessProtectionSnapshot Refresh(DateTime utcNow);
}
