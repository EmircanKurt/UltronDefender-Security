using System;

namespace AegisPC.Core.Models;

public class InstalledApplication
{
    public string DisplayName { get; set; } = string.Empty;
    public string? Publisher { get; set; }
    public string? Version { get; set; }
    public DateTime? InstallDate { get; set; }
    public long? EstimatedSizeKB { get; set; }
    public string? InstallLocation { get; set; }
    public string? UninstallString { get; set; }
    public string? DisplayIcon { get; set; }
    public string? RegistrySource { get; set; }
    public DateTime? LastKnownUsage { get; set; }
    public bool UsageReliable { get; set; }
    public int TrustLevel { get; set; }
}
