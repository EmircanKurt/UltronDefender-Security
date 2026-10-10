using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>Service-only authenticated operations require identity established by the transport, not request data.</summary>
public partial class QuarantineService
{
    /// <summary>Contains verified content only for its locked source owner or a transport-verified administrator.</summary>
    public Task<bool> TryQuarantineForCallerAsync(string path, string reason, string expectedSha256, string authenticatedSid,
        bool isAdministrator, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticatedSid);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);
        return QuarantineCoreAsync(path, reason, expectedSha256, cancellationToken, authenticatedSid, isAdministrator);
    }

    /// <summary>Lists caller-owned active records; legacy unknown owners remain administrator-only.</summary>
    public Task<List<QuarantineEntry>> GetItemsForCallerAsync(string authenticatedSid, bool isAdministrator, CancellationToken cancellationToken = default)
        => _engine.GetItemsForCallerAsync(authenticatedSid, isAdministrator, cancellationToken);

    /// <summary>Checks owner authorization under the same lease that deletes the recovery payload and updates metadata.</summary>
    public async Task<bool> DeleteForCallerAsync(int id, string authenticatedSid, bool isAdministrator, CancellationToken cancellationToken = default)
    {
        LastError = null;
        bool deleted = await _engine.DeleteForCallerAsync(id, authenticatedSid, isAdministrator, cancellationToken);
        if (!deleted) { LastError = "Kasa kaydı bulunamadı veya bu kayda erişim yetkiniz yok."; return false; }
        foreach (Action<int> observer in OnFileDeleted?.GetInvocationList() ?? Array.Empty<Delegate>())
        {
            try { observer(id); }
            catch (Exception ex) { _logger?.LogWarning(ex, "Caller-authorized deletion notification failed for entry {Id}", id); }
        }
        return true;
    }

    /// <summary>
    /// Supplies verified plaintext to a trusted streaming writer that executes all destination I/O under the caller token.
    /// The callback must publish without overwrite and not dispose its input; no SYSTEM destination write is performed.
    /// </summary>
    public async Task<bool> RestoreForCallerAsync(int id, string authenticatedSid, bool isAdministrator,
        Func<QuarantineEntry, Stream, CancellationToken, Task> authenticatedWriter, string? customDestinationPath = null,
        CancellationToken cancellationToken = default)
    {
        LastError = null;
        var restored = await _engine.ExecuteRestoreForCallerAsync(id, authenticatedSid, isAdministrator,
            authenticatedWriter, customDestinationPath, cancellationToken);
        if (!restored.Success) { LastError = restored.Message; return false; }
        try
        {
            var entry = await _engine.GetItemByIdAsync(id, CancellationToken.None);
            if (entry != null)
            {
                _exclusionService?.AddTemporaryContentExclusion(restored.RestoredPath, entry.SHA256,
                    TimeSpan.FromMinutes(5), "Restored verified content only");
                _fileHashMatcher?.InvalidateCache(restored.RestoredPath);
            }
        }
        catch (Exception ex) { _logger?.LogWarning(ex, "Post-commit recovery cache bookkeeping failed for entry {Id}", id); }
        foreach (Action<int> observer in OnFileRestored?.GetInvocationList() ?? Array.Empty<Delegate>())
        {
            try { observer(id); }
            catch (Exception ex) { _logger?.LogWarning(ex, "Caller-authorized recovery notification failed for entry {Id}", id); }
        }
        return true;
    }
}
