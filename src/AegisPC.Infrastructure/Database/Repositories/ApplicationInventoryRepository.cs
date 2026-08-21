using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class ApplicationInfo
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string? Version { get; set; }
        public string? Publisher { get; set; }
        public DateTime InstallDate { get; set; }
    }

    public class ApplicationInventoryRepository
    {
        private readonly DatabaseService _databaseService;

        public ApplicationInventoryRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task InsertAsync(ApplicationInfo app, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO ApplicationInventory (Id, Name, Version, Publisher, InstallDate)
                VALUES (@id, @name, @version, @publisher, @installDate);";

            AddParameters(command, app);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task UpdateAsync(ApplicationInfo app, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                UPDATE ApplicationInventory 
                SET Name = @name, Version = @version, Publisher = @publisher, InstallDate = @installDate
                WHERE Id = @id;";

            AddParameters(command, app);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM ApplicationInventory WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<IEnumerable<ApplicationInfo>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            var results = new List<ApplicationInfo>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Name, Version, Publisher, InstallDate FROM ApplicationInventory ORDER BY Name ASC;";

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToApp(reader));
            }
            return results;
        }

        public async Task<ApplicationInfo?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Name, Version, Publisher, InstallDate FROM ApplicationInventory WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                return MapReaderToApp(reader);
            }
            return null;
        }

        public async Task<IEnumerable<ApplicationInfo>> GetByNameAsync(string name, CancellationToken cancellationToken = default)
        {
            var results = new List<ApplicationInfo>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Id, Name, Version, Publisher, InstallDate FROM ApplicationInventory WHERE Name LIKE @name ORDER BY Name ASC;";
            command.Parameters.AddWithValue("@name", $"%{name}%");

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(MapReaderToApp(reader));
            }
            return results;
        }

        private ApplicationInfo MapReaderToApp(SqliteDataReader reader)
        {
            return new ApplicationInfo
            {
                Id = reader.GetString(0),
                Name = reader.GetString(1),
                Version = reader.IsDBNull(2) ? null : reader.GetString(2),
                Publisher = reader.IsDBNull(3) ? null : reader.GetString(3),
                InstallDate = DateTime.Parse(reader.GetString(4))
            };
        }

        private void AddParameters(SqliteCommand command, ApplicationInfo app)
        {
            command.Parameters.AddWithValue("@id", app.Id);
            command.Parameters.AddWithValue("@name", app.Name);
            command.Parameters.AddWithValue("@version", app.Version ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@publisher", app.Publisher ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@installDate", app.InstallDate.ToString("o"));
        }
    }
}
