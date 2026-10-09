using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

/// <summary>Presentation only. Never removes raw records, changes engine/cache decisions or authorizes intervention.</summary>
public static class FindingVisibilityPolicy
{
    /// <summary>Only complete current authenticated tool-only records may be hidden.</summary>
    public static bool IsVisible(SecurityFinding finding, bool showOptionalTools = false) =>
        IsVisible(finding.SoftwareClass, finding.SoftwareClassification, finding.SHA256, finding.RuleSetVersion,
            finding.InspectionComplete, finding.CoverageLimitations == null || finding.CoverageLimitations.Count != 0, finding.IsAllowlisted,
            finding.HasIndependentMalwareEvidence, finding.RiskLevel, showOptionalTools);

    /// <summary>Shared IPC/result visibility rule; incomplete and legacy metadata always remain visible.</summary>
    public static bool IsVisible(SoftwareFindingClass classification, SoftwareClassificationMetadata? metadata,
        string? sha256, string ruleVersion, bool complete, bool hasCoverageGaps, bool bypassed,
        bool independentMalware, RiskLevel risk, bool showOptionalTools = false)
    {
        return showOptionalTools || classification != SoftwareFindingClass.PotentiallyUnwantedToolOnly ||
            metadata?.Verified != true || metadata.ValidUntilUtc <= DateTime.UtcNow || !complete || hasCoverageGaps || bypassed || independentMalware ||
            risk is RiskLevel.Unknown or RiskLevel.Suspicious or RiskLevel.HighRisk or RiskLevel.ConfirmedMalicious ||
            ruleVersion != DetectionRuleSet.Version || string.IsNullOrWhiteSpace(metadata.SourceReference) ||
            string.IsNullOrWhiteSpace(metadata.IntelVersion) || sha256 is not { Length: 64 } ||
            !sha256.All(Uri.IsHexDigit) || !string.Equals(metadata.SHA256, sha256, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Optional classification alone cannot lower health or inflate malware counters, even when shown.</summary>
    public static bool IsSecurityConcern(SecurityFinding finding) => IsVisible(finding, false);
}
