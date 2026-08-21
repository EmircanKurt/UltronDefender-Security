using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class Recommendation
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string? Description { get; set; }
        public int Category { get; set; }
        public bool IsDismissed { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class RecommendationRepository
    {
        private readonly DatabaseService _databaseService;

        public RecommendationRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task InsertAsync(Recommendation rec, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO Recommendations (Id, Title, Description, Category, IsDismissed, CreatedAt)
                VALUES (@id, @title, @description, @category, @isDismissed, @createdAt);";

            command.Parameters.AddWithValue("@id", rec.Id);
            command.Parameters.AddWithValue("@title", rec.Title);
            command.Parameters.AddWithValue("@description", rec.Description ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@category", rec.Category);
            command.Parameters.AddWithValue("@isDismissed", rec.IsDismissed ? 1 : 0);
            command.Parameters.AddWithValue("@createdAt", rec.CreatedAt.ToString("o"));

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task UpdateAsync(Recommendation rec, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                UPDATE Recommendations 
                SET Title = @title, Description = @description, Category = @category, IsDismissed = @isDismissed
                WHERE Id = @id;";

            command.Parameters.AddWithValue("@id", rec.Id);
            command.Parameters.AddWithValue("@title", rec.Title);
            command.Parameters.AddWithValue("@description", rec.Description ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@category", rec.Category);
            command.Parameters.AddWithValue("@isDismissed", rec.IsDismissed ? 1 : 0);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM Recommendations WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<IEnumerable<Recommendation>> GetActiveAsync(CancellationToken cancellationToken = default)
        {
            var results = new List<Recommendation>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Title, Description, Category, IsDismissed, CreatedAt FROM Recommendations WHERE IsDismissed = 0 ORDER BY CreatedAt DESC;";

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToRecommendation(reader));
            }
            return results;
        }

        public async Task<IEnumerable<Recommendation>> GetByCategoryAsync(int category, CancellationToken cancellationToken = default)
        {
            var results = new List<Recommendation>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Title, Description, Category, IsDismissed, CreatedAt FROM Recommendations WHERE Category = @category ORDER BY CreatedAt DESC;";
            command.Parameters.AddWithValue("@category", category);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToRecommendation(reader));
            }
            return results;
        }

        public async Task DismissAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE Recommendations SET IsDismissed = 1 WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<Recommendation?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Title, Description, Category, IsDismissed, CreatedAt FROM Recommendations WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                return MapReaderToRecommendation(reader);
            }
            return null;
        }

        private Recommendation MapReaderToRecommendation(SqliteDataReader reader)
        {
            return new Recommendation
            {
                Id = reader.GetString(0),
                Title = reader.GetString(1),
                Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                Category = reader.GetInt32(3),
                IsDismissed = reader.GetInt32(4) == 1,
                CreatedAt = DateTime.Parse(reader.GetString(5))
            };
        }
    }
}
