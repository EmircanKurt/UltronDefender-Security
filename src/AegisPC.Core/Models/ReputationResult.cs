using System;

namespace AegisPC.Core.Models;

public class ReputationResult
{
    public bool IsKnown { get; set; }
    public bool IsMalicious { get; set; }
    public int DetectionCount { get; set; }
    public int TotalEngines { get; set; }
    public string Source { get; set; } = string.Empty;
    public DateTime CheckedAt { get; set; } = DateTime.UtcNow;
    public string? Details { get; set; }
}
