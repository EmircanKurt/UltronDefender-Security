namespace AegisPC.Core.Models;

/// <summary>Observed user-mode protection availability; it is not a clean-device or malware-efficacy verdict.</summary>
public enum ProtectionHealthState
{
    /// <summary>No fresh, compatible service observation is available.</summary>
    Unknown,
    /// <summary>The configured user-mode listeners are active within their reported coverage.</summary>
    Healthy,
    /// <summary>A bounded reconciliation is in progress.</summary>
    Recovering,
    /// <summary>A listener, inspection capability or coverage segment is unavailable.</summary>
    Degraded,
    /// <summary>File protection is explicitly stopped.</summary>
    Stopped
}

/// <summary>Versioned, timestamped observed health. Missing capabilities never imply enabled protection.</summary>
public sealed class ProtectionHealthSnapshot
{
    /// <summary>Actual bounded AI consumer availability; not malware detection efficacy.</summary>
    public bool BehaviorObservationActive { get; set; }
    public bool FileIoAttributionActive { get; set; }
    public int PendingBehaviorEvents { get; set; }
    public long BehaviorEventsLost { get; set; }
    public long UnattributedFileWrites { get; set; }
    public bool SignedThreatIntelProvisioned { get; set; }
    /// <summary>Watcher errors are incident counts; unknown lost-file counts are not invented.</summary>
    public long FileWatcherErrors { get; set; }
    /// <summary>Whether the service-owned device observation loop is running.</summary>
    public bool DeviceInventoryActive { get; set; }
    /// <summary>Whether the latest device/volume descriptors could all be resolved.</summary>
    public bool DeviceInventoryComplete { get; set; }
    /// <summary>Aggregate interface count; private instance identities require an authorized inventory request.</summary>
    public int ObservedDeviceInterfaces { get; set; }
    /// <summary>Inventory capture age independent of the five-second service heartbeat.</summary>
    public DateTime? DeviceInventoryCapturedAtUtc { get; set; }
    /// <summary>Wire contract version understood by the current service and UI.</summary>
    public int ProtocolVersion { get; init; } = 1;
    /// <summary>UTC time at which the service sampled its listeners.</summary>
    public DateTime CapturedAtUtc { get; init; }
    /// <summary>Current availability, independently of scan findings or desired settings.</summary>
    public ProtectionHealthState State { get; set; }
    /// <summary>Actual registered filesystem watcher count, not a promise of whole-disk coverage.</summary>
    public int WatcherCount { get; init; }
    /// <summary>Pending filesystem arrivals in bounded queues.</summary>
    public int PendingFileEvents { get; init; }
    /// <summary>Whether filesystem reconciliation is active or queued.</summary>
    public bool RecoveryPending { get; init; }
    /// <summary>Historical managed arrival loss; successful reconciliation does not erase this count.</summary>
    public long ManagedEventsLost { get; init; }
    /// <summary>Historical OS ETW event loss, or -1 when it cannot be observed.</summary>
    public long OperatingSystemEventsLost { get; init; }
    /// <summary>Whether process post-start telemetry is actually subscribed and pumping.</summary>
    public bool ProcessTelemetryActive { get; init; }
    /// <summary>Whether image-load telemetry is actually pumping.</summary>
    public bool ImageTelemetryActive { get; init; }
    /// <summary>Whether a kernel bridge is connected; false is normal for this supplemental user-mode release.</summary>
    public bool KernelBridgeConnected { get; init; }
    /// <summary>Whether production content inspection is actually connected to an AMSI provider.</summary>
    public bool AmsiContentScanningActive { get; set; }
    /// <summary>Last successful native-provider observation; null means no native request was observed.</summary>
    public DateTime? AmsiLastNativeScanUtc { get; set; }
    /// <summary>Whether a verified flow producer and enforcement pipeline are connected.</summary>
    public bool NetworkFlowInspectionActive { get; init; }
    /// <summary>Bounded explanations without other users' file paths or command lines.</summary>
    public string[] Limitations { get; set; } = [];

    /// <summary>Requires a compatible observation no older than fifteen seconds; future timestamps are rejected.</summary>
    public bool IsFresh(DateTime utcNow) => ProtocolVersion == 1 && CapturedAtUtc != default &&
        utcNow >= CapturedAtUtc && utcNow - CapturedAtUtc <= TimeSpan.FromSeconds(15);
}

