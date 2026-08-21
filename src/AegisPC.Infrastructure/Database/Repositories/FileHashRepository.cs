using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class FileHashRecord
    {
        public string FilePath { get; set; } = string.Empty;
        public string Hash { get; set; } = string.Empty;
        public DateTime LastAccessed { get; set; }
        public bool IsSafe { get; set; }
    }

    public class FileHashRepository
    {
        private readonly DatabaseService _databaseService;

        public FileHashRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task<FileHashRecord?> GetByPathAsync(string filePath, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT FilePath, Hash, LastAccessed, IsSafe FROM FileHashes WHERE FilePath = @path;";
            command.Parameters.AddWithValue("@path", filePath);

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                return new FileHashRecord
                {
                    FilePath = reader.GetString(0),
                    Hash = reader.GetString(1),
                    LastAccessed = DateTime.Parse(reader.GetString(2)),
                    IsSafe = reader.GetInt32(3) == 1
                };
            }
            return null;
        }

        public async Task InsertOrUpdateAsync(FileHashRecord record, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO FileHashes (FilePath, Hash, LastAccessed, IsSafe) 
                VALUES (@path, @hash, @lastAccessed, @isSafe)
                ON CONFLICT(FilePath) DO UPDATE SET 
                    Hash = @hash, 
                    LastAccessed = @lastAccessed, 
                    IsSafe = @isSafe;";

            command.Parameters.AddWithValue("@path", record.FilePath);
            command.Parameters.AddWithValue("@hash", record.Hash);
            command.Parameters.AddWithValue("@lastAccessed", record.LastAccessed.ToString("o"));
            command.Parameters.AddWithValue("@isSafe", record.IsSafe ? 1 : 0);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task DeleteOldAsync(int days, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM FileHashes WHERE LastAccessed < @cutoffDate;";
            command.Parameters.AddWithValue("@cutoffDate", DateTime.UtcNow.AddDays(-days).ToString("o"));

            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}
