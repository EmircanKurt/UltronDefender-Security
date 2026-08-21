using System;
using System.Collections.Generic;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class ScanResult
{
    public ScanType ScanType { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public ScanStatus Status { get; set; }
    public int TotalFiles { get; set; }
    public int ScannedFiles { get; set; }
    public int SkippedFiles { get; set; }
    public int FindingsCount => Findings.Count;
    public string? CustomPath { get; set; }
    public long ElapsedMs { get; set; }
    public List<SecurityFinding> Findings { get; set; } = new();
}
