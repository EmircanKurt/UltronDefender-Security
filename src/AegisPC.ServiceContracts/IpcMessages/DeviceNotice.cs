namespace AegisPC.ServiceContracts.IpcMessages;

/// <summary>Explainable, path-free device observation; never a malware or firmware verdict.</summary>
public sealed class DeviceNotice
{
    /// <summary>Observed function change without recording keyboard input.</summary>
    public string Message { get; set; } = string.Empty;
    /// <summary>True when storage and keyboard functions were grouped by OS container identity.</summary>
    public bool CompositeStorageKeyboard { get; set; }
}
