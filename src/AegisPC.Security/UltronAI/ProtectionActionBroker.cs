using AegisPC.Contracts.Protection;

namespace AegisPC.Security.UltronAI;

/// <summary>Bounded, single-use action gate. Recommendations and UI claims are never enforcement proof.</summary>
public sealed class ProtectionActionBroker : IProtectionActionBroker
{
    private sealed record Entry(ActionPermit Permit, ProtectionEvidenceSnapshot Snapshot, bool UserApproved);
    private readonly Dictionary<Guid, Entry> _permits = new();
    private readonly object _gate = new();
    private readonly IProtectionActionValidator _validator;
    private readonly IProtectionActionExecutor _executor;
    private readonly TimeProvider _time;
    private const int MaximumPermits = 256;

    /// <summary>Requires independently implemented proof and execution adapters; the default pilot adapter denies native operations.</summary>
    public ProtectionActionBroker(IProtectionActionValidator validator, IProtectionActionExecutor executor, TimeProvider? time = null)
    { _validator = validator; _executor = executor; _time = time ?? TimeProvider.System; }

    /// <summary>Freezes evidence and validates live provenance before issuing a 15-second caller-bound permit.</summary>
    public async Task<ActionPermit?> ProposeAsync(ProtectionEvidenceSnapshot snapshot, ProtectionActionKind kind,
        ProtectionCaller caller, bool userApproved, CancellationToken cancellationToken = default)
    {
        if (snapshot.Evidence.Count > 512 || !ValidCaller(caller) || !ValidIdentity(snapshot.File) ||
            snapshot.ObservedAtUtc > _time.GetUtcNow() || _time.GetUtcNow() - snapshot.ObservedAtUtc > TimeSpan.FromSeconds(60)) return null;
        // Startup/restore require a durable undo adapter; termination requires actor-bound file-I/O proof and a separate pilot.
        if (kind != ProtectionActionKind.Quarantine) return null;
        var frozen = snapshot with { Evidence = Array.AsReadOnly(snapshot.Evidence.ToArray()) };
        ProtectionActionValidation proof;
        try { proof = await _validator.ValidateAsync(frozen, kind, caller, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return null; }
        if (!CanPermit(proof, frozen, userApproved)) return null;
        var permit = new ActionPermit(Guid.NewGuid(), caller.OwnerSid, kind, proof.File!, proof.Process,
            proof.EvidenceRevision, UltronDecisionEngine.PolicyVersion, _time.GetUtcNow().AddSeconds(15));
        lock (_gate)
        {
            foreach (var id in _permits.Where(x => x.Value.Permit.ExpiresAtUtc <= _time.GetUtcNow()).Select(x => x.Key).ToArray()) _permits.Remove(id);
            if (_permits.Count >= MaximumPermits) return null;
            _permits.Add(permit.Id, new(permit, frozen, userApproved));
        }
        return permit;
    }

    /// <summary>Consumes once, then rejects changed content, stale proof, critical objects, wrong users or forged permit fields.</summary>
    public async Task<ActionReceipt> ExecuteAsync(ActionPermit permit, ProtectionCaller caller, CancellationToken cancellationToken = default)
    {
        Entry? entry;
        lock (_gate)
        {
            if (!_permits.TryGetValue(permit.Id, out entry)) return Receipt(permit, ProtectionActionOutcome.Rejected, "UnknownOrConsumedPermit");
            // Unauthorized guesses do not consume another user's real permit.
            if (entry.Permit != permit || !ValidCaller(caller) || permit.OwnerSid != caller.OwnerSid)
                return Receipt(permit, ProtectionActionOutcome.Rejected, "PermitIdentityMismatch");
            _permits.Remove(permit.Id);
        }
        if (permit.ExpiresAtUtc <= _time.GetUtcNow()) return Receipt(permit, ProtectionActionOutcome.Rejected, "PermitExpired");
        try
        {
            var proof = await _validator.ValidateAsync(entry.Snapshot, permit.Kind, caller, cancellationToken).ConfigureAwait(false);
            if (!CanPermit(proof, entry.Snapshot, entry.UserApproved) || proof.File != permit.File || proof.Process != permit.Process ||
                proof.EvidenceRevision != permit.EvidenceRevision)
                return Receipt(permit, ProtectionActionOutcome.Rejected, "TargetOrEvidenceChanged");
            cancellationToken.ThrowIfCancellationRequested();
            var receipt = await _executor.ExecuteAsync(permit, cancellationToken).ConfigureAwait(false);
            if (receipt.PermitId != permit.Id || receipt.Kind != permit.Kind)
                return Receipt(permit, ProtectionActionOutcome.Unknown, "InvalidExecutorReceipt");
            return receipt;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        { return Receipt(permit, ProtectionActionOutcome.Cancelled, "ExecutionCancelledOutcomeUnverified"); }
        catch (Exception) { return Receipt(permit, ProtectionActionOutcome.Unknown, "ExecutionFaultOutcomeUnverified"); }
    }

    private static bool CanPermit(ProtectionActionValidation proof, ProtectionEvidenceSnapshot snapshot, bool userApproved)
        => proof.Authorized && !proof.CriticalObject && ValidIdentity(proof.File) && proof.File == snapshot.File && proof.Process == snapshot.Process &&
            !string.IsNullOrWhiteSpace(proof.EvidenceRevision) && (proof.ConfirmedContent || userApproved);
    private static bool ValidIdentity(ProtectionFileIdentity? file) => file != null &&
        !string.IsNullOrWhiteSpace(file.VolumeId) && !string.IsNullOrWhiteSpace(file.FileId) &&
        file.SHA256.Length == 64 && file.SHA256.All(Uri.IsHexDigit);
    private static bool ValidCaller(ProtectionCaller caller) => !string.IsNullOrWhiteSpace(caller.OwnerSid) && caller.OwnerSid.StartsWith("S-1-", StringComparison.Ordinal);
    private ActionReceipt Receipt(ActionPermit permit, ProtectionActionOutcome outcome, string reason)
        => new(Guid.NewGuid(), permit.Id, permit.Kind, outcome, reason, _time.GetUtcNow());
}
