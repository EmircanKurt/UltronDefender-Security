using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Safety;

/// <summary>Records committed exclusion changes without treating an audit transport failure as a rolled-back database mutation.</summary>
internal static class ExclusionAuditWriter
{
    internal static async Task RecordAsync(IAuditLogService? audit, ILogger? logger, AuditAction action,
        ExclusionEntry entry, string details, CancellationToken cancellationToken)
    {
        if (audit == null) return;
        try
        {
            await audit.LogActionAsync(action, "ExclusionService", entry.Value, entry.Value,
                details, AuditResult.Success, null, cancellationToken);
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "Committed exclusion change could not be written to the audit log. Rule ID: {Id}, action: {Action}.",
                entry.Id, action);
        }
    }
}
