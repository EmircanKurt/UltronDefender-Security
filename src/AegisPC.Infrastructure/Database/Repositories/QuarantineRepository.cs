using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class QuarantineItem
    {
        public string Id { get; set; } = string.Empty;
        public string OriginalPath { get; set; } = string.Empty;
        public string QuarantinePath { get; set; } = string.Empty;
        public DateTime QuarantinedAt { get; set; }
        public int RiskLevel { get; set; }
        public int Status { get; set; }
    }

    public class QuarantineRepository
    {
        private readonly DatabaseService _databaseService;

        public QuarantineRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task InsertAsync(QuarantineItem item, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO QuarantineItems (Id, OriginalPath, QuarantinePath, QuarantinedAt, RiskLevel, Status)
                VALUES (@id, @originalPath, @quarantinePath, @quarantinedAt, @riskLevel, @status);";

            AddParameters(command, item);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task UpdateAsync(QuarantineItem item, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                UPDATE QuarantineItems 
                SET OriginalPath = @originalPath, QuarantinePath = @quarantinePath, 
                    RiskLevel = @riskLevel, Status = @status
                WHERE Id = @id;";

            AddParameters(command, item);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM QuarantineItems WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<IEnumerable<QuarantineItem>> GetQuarantinedAsync(CancellationToken cancellationToken = default)
        {
            var results = new List<QuarantineItem>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            // Assuming status 0 = Quarantined, 1 = Restored, 2 = Deleted
            command.CommandText = "SELECT Id, OriginalPath, QuarantinePath, QuarantinedAt, RiskLevel, Status FROM QuarantineItems WHERE Status = 0 ORDER BY QuarantinedAt DESC;";

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToItem(reader));
            }
            return results;
        }

        public async Task<QuarantineItem?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, OriginalPath, QuarantinePath, QuarantinedAt, RiskLevel, Status FROM QuarantineItems WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                return MapReaderToItem(reader);
            }
            return null;
        }

        public async Task UpdateStatusAsync(string id, int status, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE QuarantineItems SET Status = @status WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);
            command.Parameters.AddWithValue("@status", status);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        private QuarantineItem MapReaderToItem(SqliteDataReader reader)
        {
            return new QuarantineItem
            {
                Id = reader.GetString(0),
                OriginalPath = reader.GetString(1),
                QuarantinePath = reader.GetString(2),
                QuarantinedAt = DateTime.Parse(reader.GetString(3)),
                RiskLevel = reader.GetInt32(4),
                Status = reader.GetInt32(5)
            };
        }

        private void AddParameters(SqliteCommand command, QuarantineItem item)
        {
            command.Parameters.AddWithValue("@id", item.Id);
            command.Parameters.AddWithValue("@originalPath", item.OriginalPath);
            command.Parameters.AddWithValue("@quarantinePath", item.QuarantinePath);
            command.Parameters.AddWithValue("@quarantinedAt", item.QuarantinedAt.ToString("o"));
            command.Parameters.AddWithValue("@riskLevel", item.RiskLevel);
            command.Parameters.AddWithValue("@status", item.Status);
        }
    }
}
