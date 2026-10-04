namespace AegisPC.Core.Enums;
/// <summary>Persistent audit event identifiers. New values are appended so existing records keep their meaning.</summary>
public enum AuditAction
{
    ProcessTerminated, StartupDisabled, StartupEnabled, FileQuarantined, FileRestored, FileDeleted,
    AppUninstallRequested, FindingIgnored, AllowlistAdded, AllowlistRemoved, ScanStarted, ScanCompleted,
    SettingsChanged, FileBlocked, ExclusionAdded, ExclusionRemoved,
    /// <summary>A review-only observation was recorded; it does not imply confirmed malware or a containment action.</summary>
    ThreatObserved
}
