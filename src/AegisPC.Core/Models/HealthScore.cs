using System;

namespace AegisPC.Core.Models;

public class HealthScore
{
    public int OverallScore { get; set; }
    public int SecurityScore { get; set; }
    public int PerformanceScore { get; set; }
    public int StabilityScore { get; set; }
    public int StartupScore { get; set; }
    public int BrowserSecurityScore { get; set; }
    public DateTime LastCalculatedAt { get; set; } = DateTime.UtcNow;
    public int ActiveFindingsCount { get; set; }
    public int RecentCrashCount { get; set; }
    public int PendingRecommendations { get; set; }
}
