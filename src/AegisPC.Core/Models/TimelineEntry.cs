using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class TimelineEntry
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Description { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public EventSeverity Severity { get; set; }
    public string? RelatedProcessName { get; set; }
    public int? RelatedPid { get; set; }
}
