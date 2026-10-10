namespace AegisPC.Core.Enums;

public enum FindingCategory
{
    MalwareSuspicion,
    KnownMalwareHash,
    ConfirmedMalicious,
    SuspiciousScript,
    UnsignedExecutable,
    SuspiciousLocation,
    SuspiciousPersistence,
    SuspiciousNetwork,
    BrowserThreat,
    HighResourceUsage,
    SystemModification,
    PrivacyConcern,
    PotentiallyUnwantedProgram,
    PhishingUrl,
    MaliciousDownload,
    Other
}
