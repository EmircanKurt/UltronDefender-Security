using System;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;

namespace AegisPC.Security.Safety;

/// <summary>Performs verified additive ownership migration without assigning historical rows to any caller.</summary>
public partial class QuarantineVaultDatabase
{
    private void InitializeOwnerSchema(bool resetUnverifiedOwners)
    {
        using var connection = CreateConnection();
        using var check = connection.CreateCommand();
        check.CommandText = "PRAGMA table_info(QuarantineEntries);";
        bool exists = false;
        using (var reader = check.ExecuteReader())
            while (reader.Read()) exists |= reader.GetString(1).Equals("OwnerSid", StringComparison.OrdinalIgnoreCase);
        check.CommandText = "SELECT COUNT(1) FROM VaultMetadata WHERE Key = 'SourceOwnerSidV1';";
        bool marked = Convert.ToInt64(check.ExecuteScalar()) != 0;
        check.CommandText = "SELECT COUNT(1) FROM QuarantineEntries;";
        bool hasRows = Convert.ToInt64(check.ExecuteScalar()) != 0;
        if (exists && marked && !resetUnverifiedOwners) return;
        string markerValue = "fresh-schema";
        if (!exists || hasRows)
        {
            markerValue = "QuarantineVault.owner-v1." + Guid.NewGuid().ToString("N") + ".backup.db";
            using var backup = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = Path.Combine(_vaultDir, markerValue), Pooling = false }.ToString());
            backup.Open();
            connection.BackupDatabase(backup);
            using var integrity = backup.CreateCommand();
            integrity.CommandText = "PRAGMA integrity_check;";
            if (!string.Equals(integrity.ExecuteScalar()?.ToString(), "ok", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Ownership migration backup failed SQLite integrity verification.");
        }
        using var transaction = connection.BeginTransaction();
        using var migrate = connection.CreateCommand();
        migrate.Transaction = transaction;
        if (!exists)
        {
            migrate.CommandText = "ALTER TABLE QuarantineEntries ADD COLUMN OwnerSid TEXT;";
            migrate.ExecuteNonQuery();
        }
        if (hasRows && (resetUnverifiedOwners || !marked))
        {
            migrate.CommandText = "UPDATE QuarantineEntries SET OwnerSid = NULL;";
            migrate.ExecuteNonQuery();
        }
        migrate.CommandText = "INSERT INTO VaultMetadata (Key, Value) VALUES ('SourceOwnerSidV1', @Backup) ON CONFLICT(Key) DO UPDATE SET Value=excluded.Value;";
        migrate.Parameters.AddWithValue("@Backup", markerValue);
        migrate.ExecuteNonQuery();
        transaction.Commit();
    }
}
