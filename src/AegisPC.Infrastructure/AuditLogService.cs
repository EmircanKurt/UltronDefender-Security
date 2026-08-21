using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Database;
using AegisPC.Infrastructure.Database.Repositories;

namespace AegisPC.Infrastructure
{
    /// <summary>
    /// Service for writing application audit logs.
    /// </summary>
    public class AuditLogService : IAuditLogService
    {
        private readonly AuditLogRepository _repository;

        public AuditLogService(DatabaseService databaseService)
        {
            _repository = new AuditLogRepository(databaseService);
        }

        public async Task LogActionAsync(
            AuditAction action,
            string targetType,
            string targetName,
            string? targetPath = null,
            string? details = null,
            AuditResult result = AuditResult.Success,
            string? errorMessage = null,
            CancellationToken cancellationToken = default)
        {
            if (!string.IsNullOrEmpty(details))
            {
                if (details.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                    details.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                    details.Contains("cookie", StringComparison.OrdinalIgnoreCase))
                {
                    details = "[GİZLİ VERİ FİLTRELENDİ]";
                }
            }

            var entry = new AuditLogEntry
            {
                Action = action,
                TargetType = targetType,
                TargetName = targetName,
                TargetPath = targetPath,
                Details = details,
                Result = result,
                ErrorMessage = errorMessage,
                Timestamp = DateTime.UtcNow
            };

            await _repository.InsertAsync(entry, cancellationToken);
        }

        public async Task<List<AuditLogEntry>> GetLogsAsync(DateTime? from = null, DateTime? to = null, CancellationToken cancellationToken = default)
        {
            return await _repository.GetLogsAsync(from, to, cancellationToken);
        }
    }
}
