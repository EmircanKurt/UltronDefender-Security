using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class ScanHistory
    {
        public string Id { get; set; } = string.Empty;
        public int ScanType { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public int Status { get; set; }
        public int FilesScanned { get; set; }
        public int ThreatsFound { get; set; }
    }

    public class ScanHistoryRepository
    {
        private readonly DatabaseService _databaseService;

        public ScanHistoryRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task InsertAsync(ScanHistory history, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO ScanHistory (Id, ScanType, StartTime, EndTime, Status, FilesScanned, ThreatsFound)
                VALUES (@id, @scanType, @startTime, @endTime, @status, @filesScanned, @threatsFound);";

            AddParameters(command, history);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<IEnumerable<ScanHistory>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            var results = new List<ScanHistory>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, ScanType, StartTime, EndTime, Status, FilesScanned, ThreatsFound FROM ScanHistory ORDER BY StartTime DESC;";
            
            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToHistory(reader));
            }
            return results;
        }

        public async Task<IEnumerable<ScanHistory>> GetRecentAsync(int count, CancellationToken cancellationToken = default)
        {
            var results = new List<ScanHistory>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, ScanType, StartTime, EndTime, Status, FilesScanned, ThreatsFound FROM ScanHistory ORDER BY StartTime DESC LIMIT @count;";
            command.Parameters.AddWithValue("@count", count);
            
            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToHistory(reader));
            }
            return results;
        }

        public async Task UpdateAsync(ScanHistory history, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                UPDATE ScanHistory 
                SET ScanType = @scanType, StartTime = @startTime, EndTime = @endTime, Status = @status, 
                    FilesScanned = @filesScanned, ThreatsFound = @threatsFound
                WHERE Id = @id;";
            
            AddParameters(command, history);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        private ScanHistory MapReaderToHistory(SqliteDataReader reader)
        {
            return new ScanHistory
            {
                Id = reader.GetString(0),
                ScanType = reader.GetInt32(1),
                StartTime = DateTime.Parse(reader.GetString(2)),
                EndTime = reader.IsDBNull(3) ? null : DateTime.Parse(reader.GetString(3)),
                Status = reader.GetInt32(4),
                FilesScanned = reader.GetInt32(5),
                ThreatsFound = reader.GetInt32(6)
            };
        }

        private void AddParameters(SqliteCommand command, ScanHistory history)
        {
            command.Parameters.AddWithValue("@id", history.Id);
            command.Parameters.AddWithValue("@scanType", history.ScanType);
            command.Parameters.AddWithValue("@startTime", history.StartTime.ToString("o"));
            command.Parameters.AddWithValue("@endTime", history.EndTime?.ToString("o") ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@status", history.Status);
            command.Parameters.AddWithValue("@filesScanned", history.FilesScanned);
            command.Parameters.AddWithValue("@threatsFound", history.ThreatsFound);
        }
    }
}
