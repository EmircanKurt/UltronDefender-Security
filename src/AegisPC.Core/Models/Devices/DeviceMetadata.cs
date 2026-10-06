namespace AegisPC.Core.Models.Devices;

/// <summary>Observed device functions; none of these flags is a malware or trust verdict.</summary>
[Flags]
public enum DeviceFunction
{
    /// <summary>The collection's function could not be determined.</summary>
    Unknown = 0,
    /// <summary>A disk interface was enumerated.</summary>
    Storage = 1,
    /// <summary>A human interface collection was enumerated.</summary>
    Hid = 2,
    /// <summary>The HID capability reports a keyboard collection.</summary>
    Keyboard = 4,
    /// <summary>The HID capability reports a mouse collection.</summary>
    Mouse = 8
}

/// <summary>Transport association from storage descriptors and the PnP parent tree, never device authenticity.</summary>
public enum UsbAssociation
{
    /// <summary>The transport could not be resolved.</summary>
    Unknown,
    /// <summary>A USB bus or ancestor was observed.</summary>
    Usb,
    /// <summary>The complete queried ancestry did not identify a USB transport.</summary>
    NotUsb
}

/// <summary>One present PnP interface and its read-only descriptors. Device-provided names and IDs are untrusted.</summary>
public sealed record DeviceMetadata
{
    /// <summary>OS device instance identity, not a cryptographic identity.</summary>
    public string InstanceId { get; init; } = string.Empty;
    /// <summary>Device interface path used only for metadata queries.</summary>
    public string InterfacePath { get; init; } = string.Empty;
    /// <summary>Immediate parent identity when available.</summary>
    public string? ParentInstanceId { get; init; }
    /// <summary>Parent identities nearest first, bounded by the resolver.</summary>
    public IReadOnlyList<string> AncestorInstanceIds { get; init; } = Array.Empty<string>();
    /// <summary>Physical container grouping reported by Windows; null if unavailable.</summary>
    public Guid? ContainerId { get; init; }
    /// <summary>Device setup class identity if the property query succeeded.</summary>
    public Guid? ClassGuid { get; init; }
    /// <summary>Device interface class used for the enumeration.</summary>
    public Guid InterfaceClassGuid { get; init; }
    /// <summary>Display-only device description, never a trust decision.</summary>
    public string DisplayName { get; init; } = string.Empty;
    /// <summary>Observed functions, including unknown HID usage.</summary>
    public DeviceFunction Functions { get; init; }
    /// <summary>HID top-level usage page, without reading input reports.</summary>
    public ushort? HidUsagePage { get; init; }
    /// <summary>HID top-level usage, without recording keystrokes.</summary>
    public ushort? HidUsage { get; init; }
    /// <summary>Current disk number; valid only for this attachment.</summary>
    public uint? DiskNumber { get; init; }
    /// <summary>Native STORAGE_BUS_TYPE value, null when unsupported or inaccessible.</summary>
    public uint? StorageBusType { get; init; }
    /// <summary>Transport association based on queried evidence.</summary>
    public UsbAssociation UsbAssociation { get; init; }
    /// <summary>Whether this interface's identity and transport queries completed.</summary>
    public bool MetadataComplete { get; init; }
    /// <summary>Query limitation, excluding sensitive command lines or input content.</summary>
    public string? Limitation { get; init; }
}
