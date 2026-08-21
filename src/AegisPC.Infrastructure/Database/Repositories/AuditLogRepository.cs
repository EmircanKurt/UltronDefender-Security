using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Database;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class AuditLogRepository
    {
        private readonly DatabaseService _databaseService;

        public AuditLogRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task InsertAsync(AuditLogEntry entry, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO AuditLogs (Action, TargetType, TargetName, TargetPath, Details, Result, ErrorMessage, Timestamp)
                VALUES (@action, @targetType, @targetName, @targetPath, @details, @result, @errorMessage, @timestamp);";

            command.Parameters.AddWithValue("@action", (int)entry.Action);
            command.Parameters.AddWithValue("@targetType", entry.TargetType);
            command.Parameters.AddWithValue("@targetName", entry.TargetName);
            command.Parameters.AddWithValue("@targetPath", (object?)entry.TargetPath ?? DBNull.Value);
            command.Parameters.AddWithValue("@details", (object?)entry.Details ?? DBNull.Value);
            command.Parameters.AddWithValue("@result", (int)entry.Result);
            command.Parameters.AddWithValue("@errorMessage", (object?)entry.ErrorMessage ?? DBNull.Value);
            command.Parameters.AddWithValue("@timestamp", entry.Timestamp.ToString("o"));

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<List<AuditLogEntry>> GetLogsAsync(DateTime? from, DateTime? to, CancellationToken cancellationToken = default)
        {
            var results = new List<AuditLogEntry>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();

            var sql = "SELECT Id, Action, TargetType, TargetName, TargetPath, Details, Result, ErrorMessage, Timestamp FROM AuditLogs WHERE 1=1 ";

            if (from.HasValue)
            {
                sql += " AND Timestamp >= @from";
                command.Parameters.AddWithValue("@from", from.Value.ToString("o"));
            }
            if (to.HasValue)
            {
                sql += " AND Timestamp <= @to";
                command.Parameters.AddWithValue("@to", to.Value.ToString("o"));
            }

            sql += " ORDER BY Timestamp DESC;";
            command.CommandText = sql;

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToEntry(reader));
            }
            return results;
        }

        public async Task<List<AuditLogEntry>> GetRecentAsync(int limit, CancellationToken cancellationToken = default)
        {
            var results = new List<AuditLogEntry>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Action, TargetType, TargetName, TargetPath, Details, Result, ErrorMessage, Timestamp FROM AuditLogs ORDER BY Timestamp DESC LIMIT @limit;";
            command.Parameters.AddWithValue("@limit", limit);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToEntry(reader));
            }
            return results;
        }

        private static AuditLogEntry MapReaderToEntry(SqliteDataReader reader)
        {
            return new AuditLogEntry
            {
                Id = reader.GetInt32(0),
                Action = (AuditAction)reader.GetInt32(1),
                TargetType = reader.GetString(2),
                TargetName = reader.GetString(3),
                TargetPath = reader.IsDBNull(4) ? null : reader.GetString(4),
                Details = reader.IsDBNull(5) ? null : reader.GetString(5),
                Result = (AuditResult)reader.GetInt32(6),
                ErrorMessage = reader.IsDBNull(7) ? null : reader.GetString(7),
                Timestamp = DateTime.Parse(reader.GetString(8))
            };
        }
    }
}
