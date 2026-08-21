using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class QuarantineEntry
{
    public int Id { get; set; }
    public string OriginalPath { get; set; } = string.Empty;
    public string QuarantinePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string SHA256 { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public string Reason { get; set; } = string.Empty;
    public RiskLevel RiskLevel { get; set; }
    public DateTime QuarantinedAt { get; set; } = DateTime.UtcNow;
    public DateTime? RestoredAt { get; set; }
    public QuarantineStatus Status { get; set; } = QuarantineStatus.Quarantined;
}
