namespace AegisPC.Core.Models;

/// <summary>Durable, user-approved file-shield pause intent; other shields remain unchanged.</summary>
public sealed record ProtectionPauseState
{
    /// <summary>UTC restoration deadline, null only for next-service-start restoration.</summary>
    public DateTime? ResumeAtUtc { get; init; }
    /// <summary>Restores on the next protection service start, potentially earlier than reboot.</summary>
    public bool ResumeOnServiceStart { get; init; }
    /// <summary>Write-ahead recovery marker; an interrupted or failed pause must restore before its requested deadline.</summary>
    public bool RestoreImmediately { get; init; }
}
