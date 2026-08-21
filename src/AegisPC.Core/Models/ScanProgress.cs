using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class ScanProgress
{
    public ScanType ScanType { get; set; }
    public string Phase { get; set; } = string.Empty;
    public int ScannedFiles { get; set; }
    public int TotalFiles { get; set; }
    public int SkippedFiles { get; set; }
    public int FindingsCount { get; set; }
    public TimeSpan ElapsedTime { get; set; }
    public string CurrentFile { get; set; } = string.Empty;
    public bool IsCompleted { get; set; }
    public bool IsCancelled { get; set; }
    public bool IsPaused { get; set; }
    public double ProgressPercent { get; set; }
}
