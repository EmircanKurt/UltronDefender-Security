using AegisPC.Contracts.Caching;
using AegisPC.Contracts.ThreatIntelligence;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.ThreatIntelligence;

namespace AegisPC.Security.Caching;

/// <summary>Shared persistent cache validity independent of per-user finding visibility.</summary>
public static class ScanVerdictCachePolicy
{
    /// <summary>Legacy/incomplete/unversioned results require reanalysis; expired optional classification does too.</summary>
    public static bool IsCurrent(CachedScanVerdict entry) =>
        entry.RuleSetVersion == DetectionRuleSet.Version && entry.IntelIdentity == AuthoritativeThreatCatalog.CacheIdentity &&
        Sha256Identity.IsValid(entry.SHA256) && entry.InspectionComplete && !entry.PolicyBypassed && entry.CoverageLimitations is { Length: 0 } &&
        entry.Verdict != RealTimeVerdict.Unknown &&
        (entry.SoftwareClass != SoftwareFindingClass.PotentiallyUnwantedToolOnly ||
            entry.SoftwareClassification?.ValidUntilUtc > DateTime.UtcNow);
}
