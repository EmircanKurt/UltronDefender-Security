using System;
using System.Collections.Generic;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class SecurityFinding
{
    /// <summary>Separate software class; legacy records remain unclassified.</summary>
    public SoftwareFindingClass SoftwareClass { get; set; }
    /// <summary>Verified hash-bound source metadata, if available.</summary>
    public SoftwareClassificationMetadata? SoftwareClassification { get; set; }
    /// <summary>Independent concern can never be hidden by a tool classification.</summary>
    public bool HasIndependentMalwareEvidence { get; set; }
    /// <summary>A generic static capability/reference, not proof of an executed attack.</summary>
    public bool IsOrdinaryCapability { get; set; }
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
    /// <summary>Identifies the stable scanner rule set; an absent value denotes a legacy observation, not current proof.</summary>
    public string RuleSetVersion { get; set; } = string.Empty;
    /// <summary>Records whether the content inspection completed; legacy observations default to incomplete.</summary>
    public bool InspectionComplete { get; set; }
    /// <summary>Preserves bounded inspection gaps separately from risk evidence.</summary>
    public List<string> CoverageLimitations { get; set; } = new();
    public List<string> RiskReasons { get; set; } = new();
    public ConfidenceLevel ConfidenceLevel { get; set; }
    public bool IsAllowlisted { get; set; }
    public DateTime FirstObserved { get; set; } = DateTime.UtcNow;
    public DateTime LastObserved { get; set; } = DateTime.UtcNow;
    public FindingStatus Status { get; set; } = FindingStatus.Active;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
