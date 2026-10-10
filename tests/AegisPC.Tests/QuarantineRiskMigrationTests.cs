using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Safety;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Exercises legacy risk-label migration only in a newly created temporary vault.</summary>
[Collection("SequentialDiskTests")]
public sealed class QuarantineRiskMigrationTests : IDisposable
{
    private readonly string _vaultDirectory = Path.Combine(Path.GetTempPath(),
        "AegisRiskMigration_" + Guid.NewGuid().ToString("N"));

    /// <summary>Old labels are masked on read and rewritten only after an explicit backed-up maintenance step.</summary>
    [Fact]
    public async Task LegacyRiskLabel_IsBackedUpAndDowngradedWithoutRemovingEntry()
    {
        Directory.CreateDirectory(_vaultDirectory);
        using (var original = new QuarantineVaultDatabase(_vaultDirectory)) { }
        string databasePath = Path.Combine(_vaultDirectory, "QuarantineVault.db");
        using (var connection = new SqliteConnection($"Data Source={databasePath};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                DELETE FROM VaultMetadata WHERE Key = 'StructuredQuarantineRiskV2';
                INSERT INTO QuarantineEntries
                    (Id, OriginalPath, CanonicalPath, QuarantinePath, FileName, SHA256, FileSize,
                     Reason, RiskLevel, QuarantinedAt, Status)
                VALUES (42, 'C:\benign.dat', 'C:\benign.dat', 'vault_42.quar', 'benign.dat',
                        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                        12, 'Ransom appears in a display label', 4, '2026-01-01T00:00:00.0000000Z', 0);
                """;
            command.ExecuteNonQuery();
        }

        using (var migrated = new QuarantineVaultDatabase(_vaultDirectory))
        {
            var entries = await migrated.GetAllEntriesAsync();
            var entry = Assert.Single(entries);
            Assert.Equal(42, entry.Id);
            Assert.Equal(RiskLevel.Unknown, entry.RiskLevel);
            Assert.Empty(Directory.GetFiles(_vaultDirectory, "*.backup.db"));
            using (var beforeMaintenance = new SqliteConnection($"Data Source={databasePath};Mode=ReadOnly;Pooling=False"))
            {
                beforeMaintenance.Open();
                using var risk = beforeMaintenance.CreateCommand();
                risk.CommandText = "SELECT RiskLevel FROM QuarantineEntries WHERE Id = 42;";
                Assert.Equal((int)RiskLevel.ConfirmedMalicious, Convert.ToInt32(risk.ExecuteScalar()));
            }

            migrated.MigrateLegacyRiskLabelsUnderMaintenance();
            Assert.Equal(RiskLevel.Unknown, Assert.Single(await migrated.GetAllEntriesAsync()).RiskLevel);
        }

        string backupPath = Assert.Single(Directory.GetFiles(_vaultDirectory, "*.backup.db"));
        using (var backup = new SqliteConnection($"Data Source={backupPath};Mode=ReadOnly;Pooling=False"))
        {
            backup.Open();
            using var command = backup.CreateCommand();
            command.CommandText = "SELECT RiskLevel FROM QuarantineEntries WHERE Id = 42;";
            Assert.Equal((int)RiskLevel.ConfirmedMalicious, Convert.ToInt32(command.ExecuteScalar()));
        }

        using (var reopened = new QuarantineVaultDatabase(_vaultDirectory))
            Assert.Equal(RiskLevel.Unknown, Assert.Single(await reopened.GetAllEntriesAsync()).RiskLevel);
        Assert.Single(Directory.GetFiles(_vaultDirectory, "*.backup.db"));
    }

    /// <summary>A vault whose existing key cannot be opened must not rewrite legacy metadata.</summary>
    [Fact]
    public void UnreadableExistingKey_StopsBeforeLegacyRiskMigration()
    {
        Directory.CreateDirectory(_vaultDirectory);
        using (var database = new QuarantineVaultDatabase(_vaultDirectory)) { }
        string databasePath = Path.Combine(_vaultDirectory, "QuarantineVault.db");
        using (var connection = new SqliteConnection($"Data Source={databasePath};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                DELETE FROM VaultMetadata WHERE Key = 'StructuredQuarantineRiskV2';
                INSERT INTO QuarantineEntries
                    (Id, OriginalPath, CanonicalPath, QuarantinePath, FileName, SHA256, FileSize,
                     Reason, RiskLevel, QuarantinedAt, Status)
                VALUES (7, 'C:\benign.dat', 'C:\benign.dat', 'vault_7.quar', 'benign.dat',
                        'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
                        12, 'legacy display text', 4, '2026-01-01T00:00:00.0000000Z', 0);
                """;
            command.ExecuteNonQuery();
        }
        File.WriteAllBytes(Path.Combine(_vaultDirectory, "vault.key"), new byte[] { 1, 2, 3 });

        Assert.Throws<CryptographicException>(() => new TransactionalQuarantineEngine(customVaultDir: _vaultDirectory));

        using var verify = new SqliteConnection($"Data Source={databasePath};Mode=ReadOnly;Pooling=False");
        verify.Open();
        using var riskQuery = verify.CreateCommand();
        riskQuery.CommandText = "SELECT RiskLevel FROM QuarantineEntries WHERE Id = 7;";
        Assert.Equal((int)RiskLevel.ConfirmedMalicious, Convert.ToInt32(riskQuery.ExecuteScalar()));
        Assert.Empty(Directory.GetFiles(_vaultDirectory, "*.backup.db"));
    }

    /// <summary>A late legacy JSON import cannot inherit a confirmed label from its old display text.</summary>
    [Fact]
    public async Task LegacyJsonImportedAfterEmptyVaultMarker_StoresUnknownRisk()
    {
        Directory.CreateDirectory(_vaultDirectory);
        using (var empty = new QuarantineVaultDatabase(_vaultDirectory)) { }
        var legacy = new QuarantineEntry
        {
            Id = 9,
            OriginalPath = @"C:\benign.dat",
            QuarantinePath = "vault_9.quar",
            FileName = "benign.dat",
            SHA256 = new string('C', 64),
            FileSize = 12,
            Reason = "Ransom appears only in a display label",
            RiskLevel = RiskLevel.ConfirmedMalicious,
            QuarantinedAt = DateTime.UtcNow,
            Status = QuarantineStatus.Quarantined
        };
        await File.WriteAllTextAsync(Path.Combine(_vaultDirectory, "quarantine_index.json"),
            JsonSerializer.Serialize(new[] { legacy }));

        using var imported = new QuarantineVaultDatabase(_vaultDirectory);
        Assert.Equal(RiskLevel.Unknown, Assert.Single(await imported.GetAllEntriesAsync()).RiskLevel);
        using var verify = new SqliteConnection($"Data Source={Path.Combine(_vaultDirectory, "QuarantineVault.db")};Mode=ReadOnly;Pooling=False");
        verify.Open();
        using var riskQuery = verify.CreateCommand();
        riskQuery.CommandText = "SELECT RiskLevel FROM QuarantineEntries WHERE Id = 9;";
        Assert.Equal((int)RiskLevel.Unknown, Convert.ToInt32(riskQuery.ExecuteScalar()));
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_vaultDirectory)) Directory.Delete(_vaultDirectory, recursive: true);
    }
}
