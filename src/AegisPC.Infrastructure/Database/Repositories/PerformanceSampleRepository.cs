using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database.Repositories
{
    public class PerformanceSample
    {
        public string Id { get; set; } = string.Empty;
        public DateTime SampleTime { get; set; }
        public double CpuUsage { get; set; }
        public double MemoryUsage { get; set; }
        public double DiskUsage { get; set; }
    }

    public class PerformanceSampleRepository
    {
        private readonly DatabaseService _databaseService;

        public PerformanceSampleRepository(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public async Task InsertAsync(PerformanceSample sample, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO PerformanceSamples (Id, SampleTime, CpuUsage, MemoryUsage, DiskUsage)
                VALUES (@id, @sampleTime, @cpuUsage, @memoryUsage, @diskUsage);";

            command.Parameters.AddWithValue("@id", sample.Id);
            command.Parameters.AddWithValue("@sampleTime", sample.SampleTime.ToString("o"));
            command.Parameters.AddWithValue("@cpuUsage", sample.CpuUsage);
            command.Parameters.AddWithValue("@memoryUsage", sample.MemoryUsage);
            command.Parameters.AddWithValue("@diskUsage", sample.DiskUsage);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<IEnumerable<PerformanceSample>> GetSamplesAsync(DateTime from, DateTime to, CancellationToken cancellationToken = default)
        {
            var results = new List<PerformanceSample>();
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                SELECT Id, SampleTime, CpuUsage, MemoryUsage, DiskUsage 
                FROM PerformanceSamples 
                WHERE SampleTime >= @from AND SampleTime <= @to 
                ORDER BY SampleTime ASC;";
            
            command.Parameters.AddWithValue("@from", from.ToString("o"));
            command.Parameters.AddWithValue("@to", to.ToString("o"));

            using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                results.Add(new PerformanceSample
                {
                    Id = reader.GetString(0),
                    SampleTime = DateTime.Parse(reader.GetString(1)),
                    CpuUsage = reader.GetDouble(2),
                    MemoryUsage = reader.GetDouble(3),
                    DiskUsage = reader.GetDouble(4)
                });
            }
            return results;
        }

        public async Task DeleteOldAsync(int days, CancellationToken cancellationToken = default)
        {
            using var connection = _databaseService.GetConnection();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM PerformanceSamples WHERE SampleTime < @cutoffDate;";
            command.Parameters.AddWithValue("@cutoffDate", DateTime.UtcNow.AddDays(-days).ToString("o"));

            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}
