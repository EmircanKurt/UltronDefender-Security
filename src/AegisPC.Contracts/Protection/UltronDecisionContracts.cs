namespace AegisPC.Contracts.Protection;

/// <summary>Describes an evidence family for deduplication and bounded review priority; not an action authority.</summary>
public enum ProtectionEvidenceFamily { StaticStructure, Packing, Imports, Persistence, FileIo, Process, Network, ConfirmedContent }
/// <summary>Describes proposals supported by the central broker; persistent deletion and process-tree kills are absent.</summary>
public enum ProtectionActionKind { Observe, RequestReview, Quarantine, TerminateVerifiedActor, DisableStartup, Restore, RejectRemoteConnection, IsolateNetwork, ReleaseNetworkIsolation }
/// <summary>Separates proposals from observed execution outcomes.</summary>
public enum ProtectionActionOutcome { Rejected, PendingValidation, Succeeded, Failed, Cancelled, Unknown }
/// <summary>Binds file content to a native volume/file identity, not a mutable pathname.</summary>
public sealed record ProtectionFileIdentity(string VolumeId, string FileId, string SHA256);
/// <summary>Prevents PID reuse across process lifetimes or boots.</summary>
public sealed record ProtectionProcessIdentity(int Pid, DateTimeOffset StartedAtUtc, string BootId, ProtectionFileIdentity Image);
/// <summary>Contains a typed observation. UI supplied fields are not proof; the broker must independently revalidate them.</summary>
public sealed record ProtectionEvidence(string OriginEventId, string FeatureId, ProtectionEvidenceFamily Family,
    int ReviewWeight, DateTimeOffset ObservedAtUtc, string Explanation, bool ClaimsConfirmedContent = false);
/// <summary>Freezes the target and evidence set for a local policy decision.</summary>
public sealed record ProtectionEvidenceSnapshot(ProtectionFileIdentity? File, ProtectionProcessIdentity? Process,
    IReadOnlyList<ProtectionEvidence> Evidence, bool CoverageComplete, DateTimeOffset ObservedAtUtc);
/// <summary>An explainable recommendation, never permission to perform an action.</summary>
public sealed record UltronDecision(ProtectionActionKind Recommendation, int ReviewPriority,
    string PolicyVersion, IReadOnlyList<string> Reasons, bool CoverageComplete);
/// <summary>Opaque, short-lived, single-use permit bound to caller, target, evidence revision and policy.</summary>
public sealed record ActionPermit(Guid Id, string OwnerSid, ProtectionActionKind Kind, ProtectionActionTarget Target,
    string EvidenceRevision, string PolicyVersion, DateTimeOffset ExpiresAtUtc)
{
    /// <summary>Preserves the file-scoped pilot constructor without requiring non-file actions to fabricate files.</summary>
    public ActionPermit(Guid id, string ownerSid, ProtectionActionKind kind, ProtectionFileIdentity file,
        ProtectionProcessIdentity? process, string evidenceRevision, string policyVersion, DateTimeOffset expiresAtUtc)
        : this(id, ownerSid, kind, new ProtectionFileTarget(file, process), evidenceRevision, policyVersion, expiresAtUtc) { }
    /// <summary>File identity exists only for a file target; other targets deliberately return null.</summary>
    public ProtectionFileIdentity? File => (Target as ProtectionFileTarget)?.Identity;
    /// <summary>Process identity is lifetime-bound when the target carries one, never inferred from a PID.</summary>
    public ProtectionProcessIdentity? Process => Target switch
    { ProtectionFileTarget file => file.Actor, ProtectionProcessTarget process => process.Identity, _ => null };
}
/// <summary>Reports what actually happened; a permit or failed attempt must not be called successful containment.</summary>
public sealed record ActionReceipt(Guid CorrelationId, Guid? PermitId, ProtectionActionKind Kind,
    ProtectionActionOutcome Outcome, string ReasonCode, DateTimeOffset CompletedAtUtc, bool SupportsUndo = false);
/// <summary>Represents the identity supplied by an authenticated server transport, not an editable UI SID.</summary>
public sealed record ProtectionCaller(string OwnerSid, bool IsAdministrator);
/// <summary>Produces deterministic, explainable recommendations without issuing native permissions.</summary>
public interface IUltronDecisionEngine
{
    /// <summary>Computes a review-priority decision; score alone cannot authorize destructive action.</summary>
    UltronDecision Evaluate(ProtectionEvidenceSnapshot snapshot);
}
/// <summary>Provides the single entry to validated proposals and actual receipts.</summary>
public interface IProtectionActionBroker
{
    /// <summary>Accepts discriminated targets; non-file native actions remain denied until their independent pilot adapters exist.</summary>
    Task<ActionPermit?> ProposeTargetAsync(ProtectionActionRequest request, ProtectionActionKind kind,
        ProtectionCaller caller, bool userApproved, CancellationToken cancellationToken = default);
    /// <summary>Independently validates caller, content and provenance before returning an optional permit.</summary>
    Task<ActionPermit?> ProposeAsync(ProtectionEvidenceSnapshot snapshot, ProtectionActionKind kind,
        ProtectionCaller caller, bool userApproved, CancellationToken cancellationToken = default);
    /// <summary>Consumes a stored permit once and revalidates its identity immediately before execution.</summary>
    Task<ActionReceipt> ExecuteAsync(ActionPermit permit, ProtectionCaller caller, CancellationToken cancellationToken = default);
}
