using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class StartupItem
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Command { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
    }

    public class StartupItemRepository
    {
        private readonly DatabaseService _databaseService;

        public StartupItemRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task InsertAsync(StartupItem item, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO StartupItems (Id, Name, Command, Location, IsEnabled)
                VALUES (@id, @name, @command, @location, @isEnabled);";

            AddParameters(command, item);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task UpdateAsync(StartupItem item, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                UPDATE StartupItems 
                SET Name = @name, Command = @command, Location = @location, IsEnabled = @isEnabled
                WHERE Id = @id;";

            AddParameters(command, item);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM StartupItems WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<IEnumerable<StartupItem>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            var results = new List<StartupItem>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Name, Command, Location, IsEnabled FROM StartupItems ORDER BY Name ASC;";

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToItem(reader));
            }
            return results;
        }

        public async Task<IEnumerable<StartupItem>> GetEnabledAsync(CancellationToken cancellationToken = default)
        {
            var results = new List<StartupItem>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Name, Command, Location, IsEnabled FROM StartupItems WHERE IsEnabled = 1 ORDER BY Name ASC;";

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToItem(reader));
            }
            return results;
        }

        public async Task<StartupItem?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Name, Command, Location, IsEnabled FROM StartupItems WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                return MapReaderToItem(reader);
            }
            return null;
        }

        private StartupItem MapReaderToItem(SqliteDataReader reader)
        {
            return new StartupItem
            {
                Id = reader.GetString(0),
                Name = reader.GetString(1),
                Command = reader.GetString(2),
                Location = reader.GetString(3),
                IsEnabled = reader.GetInt32(4) == 1
            };
        }

        private void AddParameters(SqliteCommand command, StartupItem item)
        {
            command.Parameters.AddWithValue("@id", item.Id);
            command.Parameters.AddWithValue("@name", item.Name);
            command.Parameters.AddWithValue("@command", item.Command);
            command.Parameters.AddWithValue("@location", item.Location);
            command.Parameters.AddWithValue("@isEnabled", item.IsEnabled ? 1 : 0);
        }
    }
}
