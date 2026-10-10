namespace AegisPC.Core.Models;

/// <summary>Provides a stable provenance identifier, unlike process-local cache invalidation counters.</summary>
public static class DetectionRuleSet
{
    /// <summary>Identifies the rules that distinguish static capabilities from observed attacks.</summary>
    public const string Version = "2026-10-09-game-mod-semantics-v2";
}
