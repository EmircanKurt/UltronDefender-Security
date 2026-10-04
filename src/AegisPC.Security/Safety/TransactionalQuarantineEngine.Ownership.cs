using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Safety;

/// <summary>Authenticated caller operations keep file ownership and vault data independent of UI-supplied text.</summary>
public partial class TransactionalQuarantineEngine
{
    /// <summary>
    /// Contains only hash-bound content owned by an authenticated caller, unless the server verified administrator status.
    /// SID and administrator status must originate from the IPC token, never client request fields.
    /// </summary>
    public Task<QuarantineTransactionResult> ExecuteQuarantineForCallerAsync(QuarantineRequest request,
        string authenticatedSid, bool isAdministrator, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticatedSid);
        if (string.IsNullOrWhiteSpace(request.ExpectedSha256))
            return Task.FromResult(new QuarantineTransactionResult { Message = "Authenticated containment requires verified content identity." });
        request.ForceKillHoldingProcesses = false;
        return ExecuteQuarantineCoreAsync(request, authenticatedSid, isAdministrator, cancellationToken);
    }

    /// <summary>Returns only the authenticated owner's active entries; legacy null ownership is administrator-only.</summary>
    public async Task<List<QuarantineEntry>> GetItemsForCallerAsync(string authenticatedSid, bool isAdministrator, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticatedSid);
        return (await _database.GetActiveQuarantinedAsync(cancellationToken)).Where(e => IsAuthorized(e, authenticatedSid, isAdministrator)).ToList();
    }

    /// <summary>Deletes a caller-authorized recovery record under the same cross-process lease as containment and restore.</summary>
    public async Task<bool> DeleteForCallerAsync(int id, string authenticatedSid, bool isAdministrator, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticatedSid);
        using var operation = await VaultOperationLease.AcquireAsync(_vaultDir, cancellationToken, _customVault);
        var entry = await _database.GetEntryByIdAsync(id, cancellationToken);
        if (entry == null || !IsAuthorized(entry, authenticatedSid, isAdministrator)) return false;
        return await DeleteQuarantinedCoreAsync(id, cancellationToken);
    }

    /// <summary>
    /// Decrypts and verifies into a private bounded streaming file, then supplies the verified stream to a trusted writer.
    /// The writer must perform every destination operation under the authenticated token, publish without overwrite,
    /// and must not dispose the supplied stream. SYSTEM never opens or creates the user's destination in this path.
    /// </summary>
    public async Task<QuarantineRestoreResult> ExecuteRestoreForCallerAsync(int id, string authenticatedSid, bool isAdministrator,
        Func<QuarantineEntry, Stream, CancellationToken, Task> authenticatedWriter, string? targetOverride = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticatedSid);
        ArgumentNullException.ThrowIfNull(authenticatedWriter);
        using var operation = await VaultOperationLease.AcquireAsync(_vaultDir, cancellationToken, _customVault);
        var result = new QuarantineRestoreResult { QuarantineId = id };
        var entry = await _database.GetEntryByIdAsync(id, cancellationToken);
        if (entry == null || !IsAuthorized(entry, authenticatedSid, isAdministrator))
        { result.Message = "Recovery entry is unavailable or is not owned by the authenticated caller."; return result; }
        if (entry.Status is not QuarantineStatus.Quarantined and not QuarantineStatus.PartialFailed)
        { result.Message = "Recovery entry is not in active quarantine."; return result; }
        if (entry.SHA256.Length != 64 || !entry.SHA256.All(Uri.IsHexDigit) || entry.FileSize < 0)
        { result.Message = "Recovery metadata cannot establish content integrity."; return result; }
        byte[]? key = null;
        try
        {
            ValidateVaultPayloadPath(entry.QuarantinePath);
            string destination = _pathResolver.Resolve(string.IsNullOrWhiteSpace(targetOverride) ? entry.OriginalPath : targetOverride);
            var protectedPath = _protectedPathGuard.Evaluate(destination);
            if (protectedPath.IsProtected)
            { result.Message = "Recovery destination is protected by system policy."; return result; }
            using var vaultGuard = new FileStream(entry.QuarantinePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            string temporary = Path.Combine(_vaultDir, "verified-restore." + Guid.NewGuid().ToString("N") + ".tmp");
            await using var plaintext = new FileStream(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                81920, FileOptions.Asynchronous | FileOptions.DeleteOnClose);
            key = GetMasterKey();
            using var hash = SHA256.Create();
            await using (var hashing = new CryptoStream(plaintext, hash, CryptoStreamMode.Write, leaveOpen: true))
            {
                if (!await VaultContainerCodec.DecryptVaultStreamAsync(entry.QuarantinePath, hashing, key, cancellationToken))
                    throw new CryptographicException("Recovery container verification failed.");
                await hashing.FlushFinalBlockAsync(cancellationToken);
            }
            if (plaintext.Length != entry.FileSize || !string.Equals(Convert.ToHexString(hash.Hash!), entry.SHA256, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("Recovery plaintext integrity or length did not match its metadata.");
            plaintext.Position = 0;
            var destinationEntry = new QuarantineEntry
            {
                Id = entry.Id, OriginalPath = destination, QuarantinePath = entry.QuarantinePath,
                FileName = entry.FileName, SHA256 = entry.SHA256, FileSize = entry.FileSize, OwnerSid = entry.OwnerSid,
                Reason = entry.Reason, RiskLevel = entry.RiskLevel, Status = entry.Status, QuarantinedAt = entry.QuarantinedAt
            };
            await authenticatedWriter(destinationEntry, plaintext, cancellationToken);
            // The callback returned only after publication; cancellation can no longer undo destination state.
            result.Success = true;
            result.RestoredPath = destination;
            await _database.UpdateStatusAsync(id, QuarantineStatus.Restored, DateTime.UtcNow, CancellationToken.None);
            result.Message = "Verified recovery was published by the authenticated destination writer.";
        }
        catch (Exception ex)
        {
            result.AuditPending = result.Success;
            _logger?.LogWarning(ex, "Authenticated recovery {Id} failed or requires metadata reconciliation; published={Published}", id, result.Success);
            result.Message = result.Success ? "Recovery was published, but metadata bookkeeping requires reconciliation." : "Authenticated recovery failed: " + ex.Message;
        }
        finally { if (key != null) CryptographicOperations.ZeroMemory(key); }
        return result;
    }

    private static bool IsAuthorized(QuarantineEntry entry, string? sid, bool administrator) => administrator ||
        (!string.IsNullOrWhiteSpace(sid) && entry.OwnerSid != null && string.Equals(entry.OwnerSid, sid, StringComparison.Ordinal));

    private async Task<QuarantineEntry?> FindVerifiedDuplicateAsync(string original, string sha256,
        string? ownerSid, bool administrator, CancellationToken ct)
    {
        foreach (var entry in await _database.GetEntriesByHashAsync(sha256, ct))
        {
            if (entry.Status != QuarantineStatus.Quarantined || !IsAuthorized(entry, ownerSid, administrator) ||
                !string.Equals(entry.OriginalPath, original, StringComparison.OrdinalIgnoreCase)) continue;
            ValidateVaultPayloadPath(entry.QuarantinePath);
            if (!File.Exists(entry.QuarantinePath)) continue;
            using var guard = new FileStream(entry.QuarantinePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var hash = SHA256.Create();
            await using var sink = new CryptoStream(Stream.Null, hash, CryptoStreamMode.Write, leaveOpen: true);
            if (!await VaultContainerCodec.DecryptVaultStreamAsync(entry.QuarantinePath, sink, GetMasterKey(), ct)) continue;
            await sink.FlushFinalBlockAsync(ct);
            if (string.Equals(Convert.ToHexString(hash.Hash!), sha256, StringComparison.OrdinalIgnoreCase)) return entry;
        }
        return null;
    }

    private static QuarantineTransactionResult DuplicateResult(QuarantineEntry existing, QuarantineTransactionResult result)
    {
        result.Success = true; result.WasAlreadyQuarantined = true; result.QuarantineId = existing.Id;
        result.VaultContainerPath = existing.QuarantinePath; result.SHA256 = existing.SHA256;
        result.Status = QuarantineTransactionStatus.Committed;
        result.Message = "An existing verified quarantine recovery copy satisfies this content identity.";
        return result;
    }

    private void ValidateVaultPayloadPath(string path)
    {
        string canonical = Path.GetFullPath(path);
        if (!string.Equals(Path.GetDirectoryName(canonical), Path.GetFullPath(_vaultDir).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase) ||
            !Path.GetExtension(canonical).Equals(".quar", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Recovery payload path is outside the configured vault.");
        if (File.Exists(canonical) && (File.GetAttributes(canonical) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Recovery payload cannot be a reparse point.");
    }
}
