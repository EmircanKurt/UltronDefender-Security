using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class Recommendation
{
    public int Id { get; set; }
    public RecommendationCategory Category { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Reasoning { get; set; } = string.Empty;
    public RiskLevel RiskLevel { get; set; }
    public ImpactLevel EstimatedImpact { get; set; }
    public string ActionType { get; set; } = string.Empty;
    public string? ActionData { get; set; }
    public RecommendationStatus Status { get; set; } = RecommendationStatus.Active;
    public bool DismissedForever { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
