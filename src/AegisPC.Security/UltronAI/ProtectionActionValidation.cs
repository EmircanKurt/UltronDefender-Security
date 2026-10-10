using AegisPC.Contracts.Protection;

namespace AegisPC.Security.UltronAI;

/// <summary>Describes independently verified live proof. An action adapter must retain the native handle through execution.</summary>
public sealed record ProtectionActionValidation(bool Authorized, bool ConfirmedContent, bool ActorLinked,
    bool CriticalObject, string EvidenceRevision, ProtectionFileIdentity? File, ProtectionProcessIdentity? Process,
    string ReasonCode);
/// <summary>Implementations must resolve caller scope and native target identity independently of UI claims.</summary>
public interface IProtectionActionValidator
{
    /// <summary>Revalidates current evidence, target identity and authorization, including actor creation identity.</summary>
    Task<ProtectionActionValidation> ValidateAsync(ProtectionEvidenceSnapshot snapshot, ProtectionActionKind kind,
        ProtectionCaller caller, CancellationToken cancellationToken);
    /// <summary>
    /// Acquires live proof and retains its native target through execution. Missing implementations
    /// return no lease: a detached validation record cannot authorize a later native operation.
    /// </summary>
    Task<IValidatedProtectionTarget?> AcquireAsync(ProtectionEvidenceSnapshot snapshot, ProtectionActionKind kind,
        ProtectionCaller caller, CancellationToken cancellationToken) => Task.FromResult<IValidatedProtectionTarget?>(null);
}
/// <summary>Owns the live verified target; its implementation must keep the native handle until disposal.</summary>
public interface IValidatedProtectionTarget : IAsyncDisposable
{
    /// <summary>Proof belonging to this retained target, not to a separately reopened path or PID.</summary>
    ProtectionActionValidation Validation { get; }
}
/// <summary>Executes only against independently locked and reverified objects; never infers success from an attempted call.</summary>
public interface IProtectionActionExecutor
{
    /// <summary>Produces an observed receipt; restore/disable adapters must durably save original state first.</summary>
    Task<ActionReceipt> ExecuteAsync(ActionPermit permit, IValidatedProtectionTarget target, CancellationToken cancellationToken);
}
/// <summary>Fail-closed adapter until authenticated Guardian ownership, native identity and VM gates are connected.</summary>
public sealed class PilotGatedActionAdapter : IProtectionActionValidator, IProtectionActionExecutor
{
    /// <summary>Rejects proposals rather than trusting an asserted confirmed-malware enum or owner SID.</summary>
    public Task<ProtectionActionValidation> ValidateAsync(ProtectionEvidenceSnapshot snapshot, ProtectionActionKind kind,
        ProtectionCaller caller, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new ProtectionActionValidation(false, false, false, false, string.Empty,
            null, null, "GuardianNativeIdentityAndVmGatePending"));
    }
    /// <summary>Never touches a real process, registry, file or quarantine vault in the unapproved pilot.</summary>
    public Task<ActionReceipt> ExecuteAsync(ActionPermit permit, IValidatedProtectionTarget target, CancellationToken cancellationToken)
        => Task.FromResult(new ActionReceipt(Guid.NewGuid(), permit.Id, permit.Kind,
            ProtectionActionOutcome.PendingValidation, "GuardianNativeIdentityAndVmGatePending", DateTimeOffset.UtcNow));
}
