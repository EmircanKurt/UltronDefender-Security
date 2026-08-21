using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace AegisPC.Infrastructure.Database
{
    /// <summary>
    /// Service responsible for data retention and cleanup operations.
    /// </summary>
    public class RetentionService
    {
        private readonly DatabaseService _databaseService;
        private readonly ILogger<RetentionService> _logger;

        public RetentionService(DatabaseService databaseService, ILogger<RetentionService> logger)
        {
            _databaseService = databaseService;
            _logger = logger;
        }

        /// <summary>
        /// Runs the retention policies to clean up old data.
        /// </summary>
        public async Task RunRetentionAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Starting data retention cleanup...");
            using var connection = _databaseService.GetConnection();

            await CleanupTableAsync(connection, "PerformanceSamples", "SampleTime", DateTime.UtcNow.AddDays(-7), cancellationToken);
            await CleanupTableAsync(connection, "ProcessSamples", "SampleTime", DateTime.UtcNow.AddHours(-24), cancellationToken);
            await CleanupTableAsync(connection, "WindowsEvents", "TimeCreated", DateTime.UtcNow.AddDays(-90), cancellationToken);
            await CleanupTableAsync(connection, "CrashEvents", "CrashTime", DateTime.UtcNow.AddDays(-365), cancellationToken);
            await CleanupTableAsync(connection, "AuditLogs", "Timestamp", DateTime.UtcNow.AddDays(-365), cancellationToken);
            await CleanupTableAsync(connection, "FileHashes", "LastAccessed", DateTime.UtcNow.AddDays(-30), cancellationToken);

            // Resolved SecurityFindings older than 365 days
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM SecurityFindings WHERE Status = 1 AND UpdatedAt < @date;"; // Assuming Status 1 = Resolved
            command.Parameters.AddWithValue("@date", DateTime.UtcNow.AddDays(-365).ToString("o"));
            int deletedFindings = await command.ExecuteNonQueryAsync(cancellationToken);
            _logger.LogInformation("Cleaned up {Count} resolved SecurityFindings records.", deletedFindings);

            _logger.LogInformation("Data retention cleanup completed.");
        }

        private async Task CleanupTableAsync(SqliteConnection connection, string tableName, string dateColumn, DateTime cutoffDate, CancellationToken cancellationToken)
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"DELETE FROM {tableName} WHERE {dateColumn} < @cutoffDate;";
            command.Parameters.AddWithValue("@cutoffDate", cutoffDate.ToString("o"));
            int deletedRows = await command.ExecuteNonQueryAsync(cancellationToken);
            _logger.LogInformation("Cleaned up {Count} old {TableName} records.", deletedRows, tableName);
        }
    }
}
