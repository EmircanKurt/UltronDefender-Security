namespace AegisPC.Contracts.Protection;

/// <summary>Availability of a read-only observer; available never means that an enforcement action succeeded.</summary>
public enum SecurityObservationAvailability
{
    /// <summary>No capture or subscription has been attempted.</summary>
    Pending,
    /// <summary>The described metadata source returned a current observation.</summary>
    Available,
    /// <summary>Only part of the requested metadata or event history is available.</summary>
    Partial,
    /// <summary>The source is unavailable, denied or failed; no safe-device conclusion follows.</summary>
    Unavailable
}

/// <summary>Measured presence of the physical console user, independent of incoming remote-session input.</summary>
public enum LocalConsolePresence
{
    /// <summary>Local presence cannot be determined safely.</summary>
    Unknown,
    /// <summary>Windows reports no session attached to the physical console.</summary>
    NoLocalSession,
    /// <summary>The unlocked local console has input more recent than the policy idle threshold.</summary>
    Present,
    /// <summary>The local console has exceeded the configured idle threshold.</summary>
    Away,
    /// <summary>The local console is locked; this is not evidence of malicious activity.</summary>
    Locked
}

/// <summary>A read-only console measurement; session protocol zero denotes console, not a remote session.</summary>
public sealed record ConsolePresenceObservation
{
    /// <summary>UTC capture time; stale, missing or future measurements must not authorize intervention.</summary>
    public DateTime CapturedAtUtc { get; init; }
    /// <summary>Physical-console session ID, or null when Windows explicitly reports no console session.</summary>
    public int? SessionId { get; init; }
    /// <summary>Native session protocol; zero is console, nonzero is remote, null means unavailable.</summary>
    public ushort? ClientProtocolType { get; init; }
    /// <summary>Measured console lock state; null is unknown, not unlocked.</summary>
    public bool? IsLocked { get; init; }
    /// <summary>Measured idle time for this console only; remote input is not included.</summary>
    public TimeSpan? IdleDuration { get; init; }
    /// <summary>Whether native enumeration/querying returned a usable observation.</summary>
    public SecurityObservationAvailability Availability { get; init; }
    /// <summary>Bounded source limitation without usernames or command-line contents.</summary>
    public string? Limitation { get; init; }
}

/// <summary>Read-only physical-console sampling; construction must not register hooks or change session settings.</summary>
public interface IConsolePresenceObserver
{
    /// <summary>Captures the console's native session metadata; failures return unknown/unavailable.</summary>
    ConsolePresenceObservation Capture(DateTime utcNow);
}

/// <summary>A successful or failed remote logon observation, not a request that can be held awaiting UI approval.</summary>
public sealed record RdpLogonObservation
{
    /// <summary>Provider/record/time identity for duplicate suppression; it is not a process identity.</summary>
    public string EventIdentity { get; init; } = string.Empty;
    /// <summary>UTC event time from the log provider.</summary>
    public DateTime TimestampUtc { get; init; }
    /// <summary>Observed remote source address; missing or invalid addresses cannot produce denial proposals.</summary>
    public string RemoteAddress { get; init; } = string.Empty;
    /// <summary>Provider-reported target SID when available; unknown SIDs remain empty.</summary>
    public string TargetSid { get; init; } = string.Empty;
    /// <summary>Whether the provider reports an authentication failure rather than a session or success event.</summary>
    public bool IsAuthenticationFailure { get; init; }
    /// <summary>Whether structured provider metadata identifies a RemoteInteractive logon.</summary>
    public bool IsRdpCorrelated { get; init; }
}

/// <summary>Bounded event batch and actual subscription health; audit coverage may be incomplete even when subscribed.</summary>
public sealed record RdpLogonBatch
{
    /// <summary>UTC capture time of the batch.</summary>
    public DateTime CapturedAtUtc { get; init; }
    /// <summary>Subscription availability, independent of whether a logon occurred.</summary>
    public SecurityObservationAvailability Availability { get; init; }
    /// <summary>Limited newly observed logon records; no historical scan is implied.</summary>
    public IReadOnlyList<RdpLogonObservation> Events { get; init; } = [];
    /// <summary>Historical managed queue loss, which draining the queue does not erase.</summary>
    public long LostEvents { get; init; }
    /// <summary>Source/coverage limitations without usernames or process contents.</summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];
}

/// <summary>Service-owned read-only remote-logon subscription; no firewall or audit policy changes are permitted.</summary>
public interface IRdpLogonObservationSource : IDisposable
{
    /// <summary>Explicitly starts subscription; access failures must remain visible in subsequent batches.</summary>
    void Start();
    /// <summary>Stops only this source's subscription.</summary>
    void Stop();
    /// <summary>Drains a bounded batch of pending records without authorizing any native action.</summary>
    RdpLogonBatch Drain(DateTime utcNow);
}

/// <summary>Review-only proposal for repeated failures; it is never proof of malware or an applied network rule.</summary>
public sealed record RemoteDenialProposal
{
    /// <summary>Normalized source address associated with structured RemoteInteractive failures.</summary>
    public string RemoteAddress { get; init; } = string.Empty;
    /// <summary>Target SID if known; it is not inferred from a username.</summary>
    public string TargetSid { get; init; } = string.Empty;
    /// <summary>Number of distinct failures in the policy window when the proposal was produced.</summary>
    public int DistinctFailures { get; init; }
    /// <summary>UTC end of the suggested ten-minute denial window; no rule is installed by this proposal.</summary>
    public DateTime SuggestedUntilUtc { get; init; }
    /// <summary>Always false for this observation-only foundation.</summary>
    public bool Applied => false;
}

/// <summary>Actual remote-observer health and explainable advice; no native connection approval/denial is implemented.</summary>
public sealed record RemoteProtectionSnapshot
{
    /// <summary>UTC time at which these observations were combined.</summary>
    public DateTime CapturedAtUtc { get; init; }
    /// <summary>Measured local-console presence, never reset by a remote user's input.</summary>
    public LocalConsolePresence ConsolePresence { get; init; }
    /// <summary>Native console observation availability.</summary>
    public SecurityObservationAvailability ConsoleAvailability { get; init; }
    /// <summary>Remote-logon subscription availability; events are post-observation, not pre-connection hooks.</summary>
    public SecurityObservationAvailability LogonAvailability { get; init; }
    /// <summary>Whether the measured local presence would call for denying new RDP connections in a future approved pilot.</summary>
    public bool WouldDenyNewRdpWhileAway { get; init; }
    /// <summary>Bounded repeated-failure proposals; all report Applied=false.</summary>
    public IReadOnlyList<RemoteDenialProposal> RepeatedFailureProposals { get; init; } = [];
    /// <summary>Historical managed logon-queue loss.</summary>
    public long LostEvents { get; init; }
    /// <summary>Always false: no native firewall, disconnect, isolation or reboot action is connected.</summary>
    public bool NativeEnforcementActive => false;
    /// <summary>Bounded limitations suitable for an aggregate health display.</summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];
}

/// <summary>Combines read-only console and logon observations into deterministic, non-enforcing advice.</summary>
public interface IRemoteProtectionMonitor
{
    /// <summary>Latest capture or pending state; it is not a security guarantee.</summary>
    RemoteProtectionSnapshot CurrentSnapshot { get; }
    /// <summary>Refreshes metadata and drains pending events; does not change Windows networking.</summary>
    RemoteProtectionSnapshot Refresh(DateTime utcNow);
}
