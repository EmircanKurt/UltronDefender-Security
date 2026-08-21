using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using AegisPC.Infrastructure.Database;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class SecurityFinding
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int RiskLevel { get; set; }
        public int Status { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public string Source { get; set; } = string.Empty;
    }

    public class SecurityFindingRepository
    {
        private readonly DatabaseService _databaseService;

        public SecurityFindingRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task<IEnumerable<SecurityFinding>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            var results = new List<SecurityFinding>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Title, Description, RiskLevel, Status, CreatedAt, UpdatedAt, Source FROM SecurityFindings;";
            
            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToFinding(reader));
            }
            return results;
        }

        public async Task<SecurityFinding?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Title, Description, RiskLevel, Status, CreatedAt, UpdatedAt, Source FROM SecurityFindings WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);
            
            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                return MapReaderToFinding(reader);
            }
            return null;
        }

        public async Task<IEnumerable<SecurityFinding>> GetByRiskLevelAsync(int riskLevel, CancellationToken cancellationToken = default)
        {
            var results = new List<SecurityFinding>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Title, Description, RiskLevel, Status, CreatedAt, UpdatedAt, Source FROM SecurityFindings WHERE RiskLevel = @riskLevel;";
            command.Parameters.AddWithValue("@riskLevel", riskLevel);
            
            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToFinding(reader));
            }
            return results;
        }

        public async Task InsertAsync(SecurityFinding finding, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO SecurityFindings (Id, Title, Description, RiskLevel, Status, CreatedAt, UpdatedAt, Source) 
                VALUES (@id, @title, @desc, @risk, @status, @created, @updated, @source);";
            
            AddParameters(command, finding);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task UpdateAsync(SecurityFinding finding, CancellationToken cancellationToken = default)
        {
            finding.UpdatedAt = DateTime.UtcNow;
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                UPDATE SecurityFindings 
                SET Title = @title, Description = @desc, RiskLevel = @risk, Status = @status, 
                    UpdatedAt = @updated, Source = @source
                WHERE Id = @id;";
            
            AddParameters(command, finding);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM SecurityFindings WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<int> GetActiveCountAsync(CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            // Assuming status 0 is active
            command.CommandText = "SELECT COUNT(*) FROM SecurityFindings WHERE Status = 0;";
            var result = await command.ExecuteScalarAsync(cancellationToken);
            return Convert.ToInt32(result);
        }

        private SecurityFinding MapReaderToFinding(SqliteDataReader reader)
        {
            return new SecurityFinding
            {
                Id = reader.GetString(0),
                Title = reader.GetString(1),
                Description = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                RiskLevel = reader.GetInt32(3),
                Status = reader.GetInt32(4),
                CreatedAt = DateTime.Parse(reader.GetString(5)),
                UpdatedAt = reader.IsDBNull(6) ? null : DateTime.Parse(reader.GetString(6)),
                Source = reader.IsDBNull(7) ? string.Empty : reader.GetString(7)
            };
        }

        private void AddParameters(SqliteCommand command, SecurityFinding finding)
        {
            command.Parameters.AddWithValue("@id", finding.Id);
            command.Parameters.AddWithValue("@title", finding.Title);
            command.Parameters.AddWithValue("@desc", finding.Description ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@risk", finding.RiskLevel);
            command.Parameters.AddWithValue("@status", finding.Status);
            command.Parameters.AddWithValue("@created", finding.CreatedAt.ToString("o"));
            command.Parameters.AddWithValue("@updated", finding.UpdatedAt?.ToString("o") ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@source", finding.Source ?? (object)DBNull.Value);
        }
    }
}
