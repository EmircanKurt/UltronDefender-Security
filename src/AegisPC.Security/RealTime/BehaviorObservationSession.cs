using System;
using System.Collections.Generic;
using AegisPC.Core.Models;

namespace AegisPC.Security.RealTime;

/// <summary>
/// Bounded observation context. The reported creation identity supports correlation only;
/// it is not authenticated identity or authority to contain the actor.
/// </summary>
public class ProcessBehaviorSession
{
    /// <summary>Gets or sets the reported PID, or zero when creation identity is unavailable.</summary>
    public int RootPid { get; set; }

    /// <summary>Gets or sets the reported name, which is descriptive and never an allowlist.</summary>
    public string RootProcessName { get; set; } = string.Empty;

    /// <summary>Gets or sets the reported path; the observation engine never opens this path.</summary>
    public string RootExecutablePath { get; set; } = string.Empty;

    /// <summary>Gets or sets the reported creation time, or first event time for an Unknown actor.</summary>
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Gets or sets the local receipt time used for bounded retention.</summary>
    public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;

    /// <summary>Gets a bounded list of detached observations; no entry proves malicious intent.</summary>
    public List<BehaviorEvent> Events { get; } = new();

    /// <summary>Retains the legacy PID collection; this engine never builds or contains a PID-only tree.</summary>
    public HashSet<int> TrackedProcessTree { get; } = new();

    /// <summary>Gets or sets a heuristic review score capped below authoritative high-risk classification.</summary>
    public int CurrentRiskScore { get; set; }

    /// <summary>Retains compatibility state; this observation engine always leaves containment false.</summary>
    public bool IsContained { get; set; }

    internal bool HasCreationIdentity { get; init; }
    internal string? IncidentId { get; set; }
    internal string PublishedFeatureSignature { get; set; } = string.Empty;
}
