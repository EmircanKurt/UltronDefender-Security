using System;
using System.Collections.Generic;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class SecurityFinding
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string ObjectPath { get; set; } = string.Empty;
    public string ObjectName { get; set; } = string.Empty;
    public string? SHA256 { get; set; }
    public string? SHA1 { get; set; }
    public RiskLevel RiskLevel { get; set; }
    public int RiskScore { get; set; }
    public FindingCategory Category { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<string> RiskReasons { get; set; } = new();
    public ConfidenceLevel ConfidenceLevel { get; set; }
    public bool IsAllowlisted { get; set; }
    public DateTime FirstObserved { get; set; } = DateTime.UtcNow;
    public DateTime LastObserved { get; set; } = DateTime.UtcNow;
    public FindingStatus Status { get; set; } = FindingStatus.Active;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
