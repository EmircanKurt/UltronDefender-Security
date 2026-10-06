using AegisPC.Contracts.Protection;

namespace AegisPC.Security.UltronAI;

/// <summary>Deduplicates observations and caps each family; no number alone authorizes an action.</summary>
public sealed class UltronDecisionEngine : IUltronDecisionEngine
{
    /// <summary>Identifies this auditable local policy revision.</summary>
    public const string PolicyVersion = "ultron-chief-v1-observation";
    /// <summary>Caps input processing and ignores unidentifiable or nonfinite evidence.</summary>
    public UltronDecision Evaluate(ProtectionEvidenceSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var evidence = snapshot.Evidence.Take(512)
            .Where(e => !string.IsNullOrWhiteSpace(e.FeatureId) && !string.IsNullOrWhiteSpace(e.OriginEventId))
            .GroupBy(e => (e.OriginEventId, e.FeatureId))
            .Select(g => g.OrderByDescending(e => e.ReviewWeight).First()).ToArray();
        int priority = Math.Min(100, evidence.GroupBy(e => e.Family)
            .Sum(g => Math.Min(25, g.Sum(e => Math.Clamp(e.ReviewWeight, 0, 25)))));
        bool confirmedClaim = evidence.Any(e => e.Family == ProtectionEvidenceFamily.ConfirmedContent && e.ClaimsConfirmedContent);
        var reasons = evidence.Select(e => e.Explanation).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().Take(16).ToList();
        if (confirmedClaim) reasons.Add("Content proof must be independently revalidated by the action broker.");
        if (!snapshot.CoverageComplete) reasons.Add("Coverage is partial or unknown; absence of evidence is not a clean verdict.");
        if (snapshot.Evidence.Count > 512) reasons.Add("Evidence input budget exceeded.");
        return new(confirmedClaim ? ProtectionActionKind.Quarantine : priority >= 25 ? ProtectionActionKind.RequestReview : ProtectionActionKind.Observe,
            priority, PolicyVersion, reasons.AsReadOnly(), snapshot.CoverageComplete && snapshot.Evidence.Count <= 512);
    }
}
