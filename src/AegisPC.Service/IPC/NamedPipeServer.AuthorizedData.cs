using System.IO.Pipes;
using System.Text.Json;
using System.Security.Principal;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using AegisPC.ServiceContracts.IpcMessages;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.IPC;

public partial class NamedPipeServer
{
    private static bool IsVaultOrInventoryCommand(ServiceCommandType type) => type is
        ServiceCommandType.GetQuarantine or ServiceCommandType.GetQuarantineItem or ServiceCommandType.QuarantineFile or
        ServiceCommandType.RestoreQuarantine or ServiceCommandType.DeleteQuarantine or ServiceCommandType.GetDeviceInventory;

    private async Task ProcessAuthorizedDataCommandAsync(ServiceCommand command, PipeClientConnection client, NamedPipeServerStream pipe)
    {
        ServiceReply reply;
        try
        {
            if (command.RequestId == Guid.Empty) throw new InvalidDataException("A request identity is required.");
            using var caller = AuthenticatedPipeCaller.Capture(pipe);
            client.MayReceiveMachineThreats = caller.IsAdministrator;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(client.LifetimeToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(30));
            reply = await ExecuteAuthorizedDataAsync(command, caller, deadline.Token).ConfigureAwait(false);
        }
        catch (UnauthorizedAccessException) { reply = new() { Code = "UnauthorizedCallerOrRecord" }; }
        catch (OperationCanceledException) { reply = new() { Code = "OperationTimedOutOrCancelled" }; }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Authorized data request {Command} failed without claiming action success.", command.CommandType);
            reply = new() { Code = "ServiceOperationFailed" };
        }
        reply.RequestId = command.RequestId;
        string serialized = JsonSerializer.Serialize(reply);
        if (serialized.Length > 240_000) serialized = JsonSerializer.Serialize(new ServiceReply { RequestId = command.RequestId, Code = "ResponseBudgetExceeded" });
        await SendResponseAsync(client, "Reply:" + serialized).ConfigureAwait(false);
    }

    private async Task<ServiceReply> ExecuteAuthorizedDataAsync(ServiceCommand command, AuthenticatedPipeCaller caller, CancellationToken ct)
    {
        if (command.CommandType == ServiceCommandType.GetDeviceInventory)
        {
            if (!caller.IsAdministrator) throw new UnauthorizedAccessException();
            return _devices == null ? new() { Code = "DeviceInventoryUnavailable" }
                : new() { Success = true, Code = "ObservedInventoryNotFirmwareTrust", Payload = JsonSerializer.Serialize(new
                { Inventory = _devices.CurrentSnapshot, WatchedRoots = _realTimeProtectionEngine.WatchedLocations,
                    MediaInspections = (_realTimeProtectionEngine as AegisPC.Security.RealTime.IRemovableMediaProtection)?.GetMediaInspections() }) };
        }
        if (_vault == null) return new() { Code = "VaultServiceUnavailable" };
        // SID ownership alone does not prove an interactive, trusted application request.
        // Keep mutations closed even if a future client requests a stronger impersonation token.
        if (VaultMutationPilotPolicy.RequiresAuthenticatedApproval(command.CommandType))
            return new() { Code = "InteractiveApprovalAndAuthenticatedApplicationRequired" };
        var request = JsonSerializer.Deserialize<AuthorizedVaultRequest>(command.Payload ?? "{}") ?? throw new InvalidDataException();
        if (command.CommandType == ServiceCommandType.GetQuarantine)
        {
            if (request.AfterId < 0) throw new InvalidDataException();
            var available = _vault is QuarantineService ownedService
                ? await ownedService.GetItemsForCallerAsync(caller.Sid, caller.IsAdministrator, ct).ConfigureAwait(false)
                : await _vault.GetQuarantinedItemsAsync(ct).ConfigureAwait(false);
            var visible = available
                .Where(x => x.Id > request.AfterId && QuarantineAccessPolicy.CanAccess(x, caller.Sid, caller.IsAdministrator))
                .OrderBy(x => x.Id).Take(33).ToArray();
            var page = new QuarantinePage { Entries = visible.Take(32).ToList(), NextAfterId = visible.Length > 32 ? visible[31].Id : null };
            return new() { Success = true, Payload = JsonSerializer.Serialize(page) };
        }
        if (command.CommandType == ServiceCommandType.QuarantineFile)
            return await QuarantineCandidateAsync(request, caller, ct).ConfigureAwait(false);
        var entry = await _vault.GetItemByIdAsync(request.Id, ct).ConfigureAwait(false);
        if (entry == null || !QuarantineAccessPolicy.CanAccess(entry, caller.Sid, caller.IsAdministrator)) throw new UnauthorizedAccessException();
        if (command.CommandType == ServiceCommandType.GetQuarantineItem)
            return new() { Success = true, Payload = JsonSerializer.Serialize(entry) };
        if (command.CommandType == ServiceCommandType.DeleteQuarantine)
            return _vault is QuarantineService deletionService
                ? new() { Success = await deletionService.DeleteForCallerAsync(entry.Id, caller.Sid, caller.IsAdministrator, ct).ConfigureAwait(false), Code = "DeleteResult" }
                : new() { Code = "AuthorizedDeleteNotSupported" };
        if (command.CommandType == ServiceCommandType.RestoreQuarantine)
        {
            if (!caller.IsAdministrator && request.Destination != null) throw new UnauthorizedAccessException();
            // Do not upgrade an Identification token via the process primary token: a restricted
            // thread could otherwise gain its process's rights. A mutually authenticated transport
            // and multi-user VM gate are required before this caller-context operation is enabled.
            if (!caller.CanPerformCallerContextIo) return new() { Code = "CallerContextTokenUnavailable" };
            if (_vault is not QuarantineService service) return new() { Code = "AuthorizedRestoreNotSupported" };
            bool restored = await service.RestoreForCallerAsync(entry.Id, caller.Sid, caller.IsAdministrator,
                (record, plaintext, cancellation) => CallerContextRestoreWriter.WriteAsync(caller.Identity, record, plaintext, request.Destination, cancellation), request.Destination, ct).ConfigureAwait(false);
            return new() { Success = restored, Code = restored ? "Restored" : "RestoreNotCompleted" };
        }
        return new() { Code = "UnsupportedRequest" };
    }

    private async Task<ServiceReply> QuarantineCandidateAsync(AuthorizedVaultRequest request, AuthenticatedPipeCaller caller, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Path) || _vault is not QuarantineService service) return new() { Code = "InvalidCandidate" };
        if (!caller.CanPerformCallerContextIo) return new() { Code = "CallerContextTokenUnavailable" };
        var verdict = await WindowsIdentity.RunImpersonatedAsync(caller.Identity.AccessToken,
            () => _realTimeProtectionEngine.InspectFileAsync(request.Path, ct)).ConfigureAwait(false);
        if (verdict.Verdict != RealTimeVerdict.ConfirmedMalicious || verdict.SHA256.Length != 64)
            return new() { Code = "NoConfirmedServiceEvidence" };
        bool quarantined = await service.TryQuarantineForCallerAsync(request.Path, verdict.ThreatDescription, verdict.SHA256,
            caller.Sid, caller.IsAdministrator, ct).ConfigureAwait(false);
        if (!quarantined) return new() { Code = "QuarantineNotCompleted" };
        string? payload = null;
        try
        {
            var entry = (await service.GetItemsForCallerAsync(caller.Sid, caller.IsAdministrator, CancellationToken.None).ConfigureAwait(false))
                .FirstOrDefault(x => string.Equals(x.SHA256, verdict.SHA256, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(x.OriginalPath, request.Path, StringComparison.OrdinalIgnoreCase));
            if (entry != null) payload = JsonSerializer.Serialize(entry);
        }
        catch (Exception exception) { _logger.LogWarning(exception, "Quarantine committed; optional entry notification could not be loaded."); }
        return new() { Success = true, Code = "Quarantined", Payload = payload };
    }
}
