using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class CrashEvent
    {
        public string Id { get; set; } = string.Empty;
        public string ProcessName { get; set; } = string.Empty;
        public DateTime CrashTime { get; set; }
        public string? ExceptionCode { get; set; }
        public string? StackTrace { get; set; }
    }

    public class CrashEventRepository
    {
        private readonly DatabaseService _databaseService;

        public CrashEventRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task InsertAsync(CrashEvent crashEvent, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO CrashEvents (Id, ProcessName, CrashTime, ExceptionCode, StackTrace)
                VALUES (@id, @processName, @crashTime, @exceptionCode, @stackTrace);";

            command.Parameters.AddWithValue("@id", crashEvent.Id);
            command.Parameters.AddWithValue("@processName", crashEvent.ProcessName);
            command.Parameters.AddWithValue("@crashTime", crashEvent.CrashTime.ToString("o"));
            command.Parameters.AddWithValue("@exceptionCode", crashEvent.ExceptionCode ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@stackTrace", crashEvent.StackTrace ?? (object)DBNull.Value);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<IEnumerable<CrashEvent>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            var results = new List<CrashEvent>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, ProcessName, CrashTime, ExceptionCode, StackTrace FROM CrashEvents ORDER BY CrashTime DESC;";

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToEvent(reader));
            }
            return results;
        }

        public async Task<IEnumerable<CrashEvent>> GetRecentAsync(TimeSpan duration, CancellationToken cancellationToken = default)
        {
            var cutoffTime = DateTime.UtcNow.Subtract(duration).ToString("o");
            var results = new List<CrashEvent>();
            
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, ProcessName, CrashTime, ExceptionCode, StackTrace FROM CrashEvents WHERE CrashTime >= @cutoffTime ORDER BY CrashTime DESC;";
            command.Parameters.AddWithValue("@cutoffTime", cutoffTime);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToEvent(reader));
            }
            return results;
        }

        public async Task<CrashEvent?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, ProcessName, CrashTime, ExceptionCode, StackTrace FROM CrashEvents WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                return MapReaderToEvent(reader);
            }
            return null;
        }

        private CrashEvent MapReaderToEvent(SqliteDataReader reader)
        {
            return new CrashEvent
            {
                Id = reader.GetString(0),
                ProcessName = reader.GetString(1),
                CrashTime = DateTime.Parse(reader.GetString(2)),
                ExceptionCode = reader.IsDBNull(3) ? null : reader.GetString(3),
                StackTrace = reader.IsDBNull(4) ? null : reader.GetString(4)
            };
        }
    }
}
