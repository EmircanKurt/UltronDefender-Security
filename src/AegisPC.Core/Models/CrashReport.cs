using System.Collections.Generic;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class CrashReport
{
    public CrashEvent CrashEvent { get; set; } = new();
    public List<TimelineEntry> TimelineEntries { get; set; } = new();
    public List<string> ContributingFactors { get; set; } = new();
    public List<string> RecommendedActions { get; set; } = new();
    public ConfidenceLevel ConfidenceLevel { get; set; }
    public string Summary { get; set; } = string.Empty;
}
