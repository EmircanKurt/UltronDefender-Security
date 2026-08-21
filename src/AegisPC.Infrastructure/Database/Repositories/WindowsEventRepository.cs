using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class WindowsEvent
    {
        public string Id { get; set; } = string.Empty;
        public string ProviderName { get; set; } = string.Empty;
        public int EventId { get; set; }
        public DateTime TimeCreated { get; set; }
        public int Level { get; set; }
        public string? Message { get; set; }
    }

    public class WindowsEventRepository
    {
        private readonly DatabaseService _databaseService;

        public WindowsEventRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task InsertAsync(WindowsEvent winEvent, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO WindowsEvents (Id, ProviderName, EventId, TimeCreated, Level, Message)
                VALUES (@id, @providerName, @eventId, @timeCreated, @level, @message);";

            command.Parameters.AddWithValue("@id", winEvent.Id);
            command.Parameters.AddWithValue("@providerName", winEvent.ProviderName);
            command.Parameters.AddWithValue("@eventId", winEvent.EventId);
            command.Parameters.AddWithValue("@timeCreated", winEvent.TimeCreated.ToString("o"));
            command.Parameters.AddWithValue("@level", winEvent.Level);
            command.Parameters.AddWithValue("@message", winEvent.Message ?? (object)DBNull.Value);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<IEnumerable<WindowsEvent>> GetRecentAsync(int limit, CancellationToken cancellationToken = default)
        {
            var results = new List<WindowsEvent>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, ProviderName, EventId, TimeCreated, Level, Message FROM WindowsEvents ORDER BY TimeCreated DESC LIMIT @limit;";
            command.Parameters.AddWithValue("@limit", limit);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToEvent(reader));
            }
            return results;
        }

        public async Task<IEnumerable<WindowsEvent>> GetByProviderAsync(string providerName, int limit, CancellationToken cancellationToken = default)
        {
            var results = new List<WindowsEvent>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, ProviderName, EventId, TimeCreated, Level, Message FROM WindowsEvents WHERE ProviderName = @providerName ORDER BY TimeCreated DESC LIMIT @limit;";
            command.Parameters.AddWithValue("@providerName", providerName);
            command.Parameters.AddWithValue("@limit", limit);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToEvent(reader));
            }
            return results;
        }

        public async Task DeleteOldAsync(int days, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM WindowsEvents WHERE TimeCreated < @cutoffDate;";
            command.Parameters.AddWithValue("@cutoffDate", DateTime.UtcNow.AddDays(-days).ToString("o"));

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        private WindowsEvent MapReaderToEvent(SqliteDataReader reader)
        {
            return new WindowsEvent
            {
                Id = reader.GetString(0),
                ProviderName = reader.GetString(1),
                EventId = reader.GetInt32(2),
                TimeCreated = DateTime.Parse(reader.GetString(3)),
                Level = reader.GetInt32(4),
                Message = reader.IsDBNull(5) ? null : reader.GetString(5)
            };
        }
    }
}
