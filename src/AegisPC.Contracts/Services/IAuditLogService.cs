using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IAuditLogService
{
    Task LogActionAsync(AuditAction action, string targetType, string targetName, string? targetPath = null, string? details = null, AuditResult result = AuditResult.Success, string? errorMessage = null, CancellationToken cancellationToken = default);
    Task<List<AuditLogEntry>> GetLogsAsync(DateTime? from = null, DateTime? to = null, CancellationToken cancellationToken = default);
}
