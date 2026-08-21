using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace AegisPC.Infrastructure.Database
{
    /// <summary>
    /// Handles database schema versioning and migrations.
    /// </summary>
    public class DatabaseMigration
    {
        private readonly DatabaseService _databaseService;
        private readonly ILogger<DatabaseMigration> _logger;

        public DatabaseMigration(DatabaseService databaseService, ILogger<DatabaseMigration> logger)
        {
            _databaseService = databaseService;
            _logger = logger;
        }

        /// <summary>
        /// Applies any pending migrations to the database.
        /// </summary>
        public async Task ApplyMigrationsAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Checking database migrations...");
            
            using var connection = _databaseService.GetConnection();
            var currentVersion = await GetCurrentVersionAsync(connection, cancellationToken);

            if (currentVersion < 1)
            {
                _logger.LogInformation("Applying migration version 1.");
                await ApplyMigration1Async(connection, cancellationToken);
                await SetVersionAsync(connection, 1, cancellationToken);
            }
            
            _logger.LogInformation("Database migrations up to date.");
        }

        private async Task<int> GetCurrentVersionAsync(SqliteConnection connection, CancellationToken cancellationToken)
        {
            try
            {
                using var command = connection.CreateCommand();
                command.CommandText = "SELECT MAX(Version) FROM SchemaVersion;";
                var result = await command.ExecuteScalarAsync(cancellationToken);
                
                return result != DBNull.Value && result != null ? Convert.ToInt32(result) : 0;
            }
            catch (SqliteException)
            {
                // Table might not exist yet
                return 0;
            }
        }

        private async Task SetVersionAsync(SqliteConnection connection, int version, CancellationToken cancellationToken)
        {
            using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO SchemaVersion (Version, AppliedAt) VALUES (@version, @appliedAt);";
            command.Parameters.AddWithValue("@version", version);
            command.Parameters.AddWithValue("@appliedAt", DateTime.UtcNow.ToString("o"));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        private async Task ApplyMigration1Async(SqliteConnection connection, CancellationToken cancellationToken)
        {
            // Migration 1 is implicitly applied by DatabaseService.InitializeAsync, 
            // but we can add further structural changes here in the future.
            await Task.CompletedTask;
        }
    }
}
