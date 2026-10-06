namespace AegisPC.Contracts.Protection;

/// <summary>Discriminated target identity. Its presence is a proposal, never independent authorization.</summary>
public abstract record ProtectionActionTarget;
/// <summary>Content-bound file target with an optional independently correlated process lifetime.</summary>
public sealed record ProtectionFileTarget(ProtectionFileIdentity Identity, ProtectionProcessIdentity? Actor = null) : ProtectionActionTarget;
/// <summary>Process-only target; never invents a file identity to fit another action's schema.</summary>
public sealed record ProtectionProcessTarget(ProtectionProcessIdentity Identity) : ProtectionActionTarget;
/// <summary>One remote source, listener and user/session scope; does not authorize arbitrary IP-wide blocking.</summary>
public sealed record ProtectionRemoteTarget(string SourceAddress, ushort ListenerPort, string Protocol,
    int LocalSessionId, string OwnerSid) : ProtectionActionTarget;
/// <summary>An explicitly named, owned and time-limited network scope, not a request to disable an adapter.</summary>
public sealed record ProtectionNetworkTarget(string ScopeId, DateTimeOffset RequestedUntilUtc) : ProtectionActionTarget;
/// <summary>Typed target and evidence supplied for independent validation; UI claims cannot substitute for native proof.</summary>
public sealed record ProtectionActionRequest(ProtectionActionTarget Target, IReadOnlyList<ProtectionEvidence> Evidence,
    bool CoverageComplete, DateTimeOffset ObservedAtUtc);
