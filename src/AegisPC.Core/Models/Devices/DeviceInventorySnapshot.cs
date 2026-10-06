namespace AegisPC.Core.Models.Devices;

/// <summary>A mounted or discoverable volume, addressed by volume GUID rather than a reusable drive letter.</summary>
public sealed record MediaVolumeMetadata
{
    /// <summary>Windows volume GUID path, including its trailing separator.</summary>
    public string VolumeGuid { get; init; } = string.Empty;
    /// <summary>Current drive-letter and mounted-directory paths; empty does not mean clean.</summary>
    public IReadOnlyList<string> MountPaths { get; init; } = Array.Empty<string>();
    /// <summary>Underlying current disk numbers; empty when the mapping cannot be queried.</summary>
    public IReadOnlyList<uint> DiskNumbers { get; init; } = Array.Empty<uint>();
    /// <summary>Associated current PnP disk identities, excluding letter-only matching.</summary>
    public IReadOnlyList<string> DeviceInstanceIds { get; init; } = Array.Empty<string>();
    /// <summary>Whether file-system metadata is readable now; it is not a scan verdict.</summary>
    public bool IsReady { get; init; }
    /// <summary>The OS drive type; fixed disks may still use USB.</summary>
    public DriveType DriveType { get; init; }
    /// <summary>Native STORAGE_BUS_TYPE from the volume or its physical disks, when available.</summary>
    public uint? StorageBusType { get; init; }
    /// <summary>USB association remains unknown when the evidence cannot be queried.</summary>
    public UsbAssociation UsbAssociation { get; init; }
    /// <summary>A descriptor or file-system access limitation.</summary>
    public string? Limitation { get; init; }
}

/// <summary>Immutable inventory result. Completeness describes discovery, not threat detection.</summary>
public sealed class DeviceInventorySnapshot
{
    /// <summary>Copies all collections so later producer changes cannot mutate a published snapshot.</summary>
    public DeviceInventorySnapshot(IEnumerable<DeviceMetadata> devices, IEnumerable<MediaVolumeMetadata> volumes,
        bool isComplete, string? failureReason = null, DateTime? capturedAtUtc = null, bool? presenceComplete = null)
    {
        Devices = Array.AsReadOnly(devices.Select(d => d with
        { AncestorInstanceIds = Array.AsReadOnly(d.AncestorInstanceIds.ToArray()) }).ToArray());
        Volumes = Array.AsReadOnly(volumes.Select(v => v with
        {
            MountPaths = Array.AsReadOnly(v.MountPaths.ToArray()),
            DiskNumbers = Array.AsReadOnly(v.DiskNumbers.ToArray()),
            DeviceInstanceIds = Array.AsReadOnly(v.DeviceInstanceIds.ToArray())
        }).ToArray());
        IsComplete = isComplete;
        PresenceComplete = presenceComplete ?? isComplete;
        FailureReason = failureReason;
        CapturedAtUtc = capturedAtUtc ?? DateTime.UtcNow;
    }

    /// <summary>Present disk and HID interfaces with bounded metadata.</summary>
    public IReadOnlyList<DeviceMetadata> Devices { get; }
    /// <summary>Local volume identities and current attachment information.</summary>
    public IReadOnlyList<MediaVolumeMetadata> Volumes { get; }
    /// <summary>False for registration, enumeration or bounded-query gaps.</summary>
    public bool IsComplete { get; }
    /// <summary>Whether volume membership enumeration completed, even if device or transport metadata was unavailable.</summary>
    public bool PresenceComplete { get; }
    /// <summary>Discovery gap description; unavailable must not be presented as safe.</summary>
    public string? FailureReason { get; }
    /// <summary>UTC capture time used to reject stale UI status.</summary>
    public DateTime CapturedAtUtc { get; }
}

/// <summary>One volume's current insertion, cancelled before removal or generation replacement.</summary>
public sealed record MediaVolumeSession
{
    /// <summary>The volume metadata captured for this insertion.</summary>
    public required MediaVolumeMetadata Volume { get; init; }
    /// <summary>Unique generation; a drive letter is never a session identity.</summary>
    public Guid Generation { get; init; } = Guid.NewGuid();
    /// <summary>Cancellation owned by discovery and linked to service shutdown.</summary>
    public CancellationToken InsertionCancellation { get; init; }
}

/// <summary>Small device callback signal; native callbacks enqueue this and do no file scanning.</summary>
public sealed record DeviceDiscoverySignal
{
    /// <summary>Interface arrival, removal, or reconciliation request.</summary>
    public DeviceDiscoverySignalKind Kind { get; init; }
    /// <summary>Interface path for immediate removal correlation, bounded by the native adapter.</summary>
    public string InterfacePath { get; init; } = string.Empty;
}

/// <summary>Discovery trigger; it does not authorize blocking a device.</summary>
public enum DeviceDiscoverySignalKind
{
    /// <summary>A device interface became available.</summary>
    Arrival,
    /// <summary>A device interface was removed.</summary>
    Removal,
    /// <summary>Refresh the current inventory after startup or an event gap.</summary>
    Reconcile
}
