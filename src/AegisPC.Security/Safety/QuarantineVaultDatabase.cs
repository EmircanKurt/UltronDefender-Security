using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Safety
{
    /// <summary>
    /// SQLite tabanlı, WAL modunda çalışan, ACID işlem garantili ve kayıpsız migrasyon destekli Karantina Veritabanı.
    /// </summary>
    public partial class QuarantineVaultDatabase : IDisposable
    {
        private readonly string _vaultDir;
        private readonly string _dbPath;
        private readonly string _connectionString;
        private readonly string _jsonIndexFilePath;
        private readonly ILogger? _logger;
        private readonly object _syncLock = new();
        private volatile bool _riskMigrationApplied;

        // Eşzamanlı işlemlerde yarış durumlarını ve mükerrer karantinayı engelleyen eşzamanlı kilit haritası
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> _pathLocks = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> _hashLocks = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Initializes backed-up additive schema changes; existing record ownership is never inferred.</summary>
        public QuarantineVaultDatabase(string vaultDir, ILogger? logger = null, bool operationLockHeld = false, bool resetUnverifiedOwners = false)
        {
            _vaultDir = vaultDir;
            _logger = logger;
            _dbPath = Path.Combine(vaultDir, "QuarantineVault.db");
            _connectionString = new SqliteConnectionStringBuilder { DataSource = _dbPath, Pooling = false }.ToString();
            _jsonIndexFilePath = Path.Combine(vaultDir, "quarantine_index.json");

            Directory.CreateDirectory(_vaultDir);
            // Direct database construction is a trusted custom-vault/test API. Production uses the engine's service-owned lease.
            using var initialization = operationLockHeld ? null : VaultOperationLease.AcquireAsync(_vaultDir, customVault: true).GetAwaiter().GetResult();
            InitializeDatabase();
            InitializeOwnerSchema(resetUnverifiedOwners);
            MigrateLegacyJsonIndex();
            InitializeRiskMigrationState();
            InitializeNextId();
            if (_riskMigrationApplied &&
                (File.Exists(_jsonIndexFilePath) || GetAllEntriesAsync().GetAwaiter().GetResult().Count > 0))
            {
                SyncJsonMirror();
            }
        }

        private void InitializeRiskMigrationState()
        {
            using var connection = CreateConnection();
            using var transaction = connection.BeginTransaction();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "SELECT COUNT(1) FROM VaultMetadata WHERE Key = 'StructuredQuarantineRiskV2';";
            if (Convert.ToInt64(command.ExecuteScalar()) != 0)
            {
                transaction.Commit();
                _riskMigrationApplied = true;
                return;
            }

            command.CommandText = "SELECT COUNT(1) FROM QuarantineEntries;";
            if (Convert.ToInt64(command.ExecuteScalar()) == 0)
            {
                // The write transaction makes the empty check and schema marker atomic.
                command.CommandText = "INSERT INTO VaultMetadata (Key, Value) VALUES ('StructuredQuarantineRiskV2', 'empty-vault');";
                command.ExecuteNonQuery();
                transaction.Commit();
                _riskMigrationApplied = true;
            }
            else
            {
                transaction.Commit();
                _logger?.LogWarning("Legacy quarantine risk labels are displayed as Unknown until an offline, backed-up migration is authorized.");
            }
        }

        /// <summary>
        /// Backs up and normalizes legacy risk labels only during a maintenance window in which
        /// all vault writers are stopped. It never restores an older snapshot over newer rows.
        /// </summary>
        public void MigrateLegacyRiskLabelsUnderMaintenance()
        {
            lock (_syncLock)
            {
                NormalizeLegacyRiskLabels();
                _riskMigrationApplied = true;
                SyncJsonMirror();
            }
        }

        private SqliteConnection CreateConnection()
        {
            var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var settings = connection.CreateCommand();
            settings.CommandText = "PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;";
            settings.ExecuteNonQuery();
            return connection;
        }

        private void InitializeDatabase()
        {
            using var connection = CreateConnection();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS QuarantineEntries (
                    Id INTEGER PRIMARY KEY,
                    OriginalPath TEXT NOT NULL,
                    CanonicalPath TEXT NOT NULL,
                    QuarantinePath TEXT NOT NULL,
                    FileName TEXT NOT NULL,
                    SHA256 TEXT NOT NULL,
                    FileSize INTEGER NOT NULL,
                    Reason TEXT NOT NULL,
                    RiskLevel INTEGER NOT NULL,
                    QuarantinedAt TEXT NOT NULL,
                    RestoredAt TEXT,
                    Status INTEGER NOT NULL,
                    OwnerSid TEXT
                );

                CREATE INDEX IF NOT EXISTS IX_Quarantine_SHA256 ON QuarantineEntries (SHA256);
                CREATE INDEX IF NOT EXISTS IX_Quarantine_CanonicalPath ON QuarantineEntries (CanonicalPath);
                CREATE INDEX IF NOT EXISTS IX_Quarantine_Status ON QuarantineEntries (Status);
                CREATE TABLE IF NOT EXISTS VaultSequence (Id INTEGER PRIMARY KEY CHECK (Id = 1), Value INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS VaultMetadata (Key TEXT PRIMARY KEY, Value TEXT NOT NULL);
                INSERT OR IGNORE INTO VaultSequence (Id, Value) VALUES (1, 0);
            ";
            cmd.ExecuteNonQuery();
        }

        private void NormalizeLegacyRiskLabels()
        {
            // Earlier releases inferred the persisted tier from display text. There is no
            // reliable way to reconstruct detector evidence from those rows, so preserve an
            // SQLite snapshot and mark pre-schema entries Unknown before publishing them.
            const string migrationKey = "StructuredQuarantineRiskV2";
            using var connection = CreateConnection();
            using var markerCheck = connection.CreateCommand();
            markerCheck.CommandText = "SELECT COUNT(1) FROM VaultMetadata WHERE Key = @Key;";
            markerCheck.Parameters.AddWithValue("@Key", migrationKey);
            if (Convert.ToInt64(markerCheck.ExecuteScalar()) != 0) return;

            using var count = connection.CreateCommand();
            count.CommandText = "SELECT COUNT(1) FROM QuarantineEntries;";
            long legacyCount = Convert.ToInt64(count.ExecuteScalar());
            string? backupName = null;
            long backedUpMaxId = 0;
            if (legacyCount > 0)
            {
                backupName = "QuarantineVault.risk-v2." + Guid.NewGuid().ToString("N") + ".backup.db";
                string backupPath = Path.Combine(_vaultDir, backupName);
                using (var backup = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = backupPath,
                    Mode = SqliteOpenMode.ReadWriteCreate,
                    Pooling = false
                }.ToString()))
                {
                    backup.Open();
                    connection.BackupDatabase(backup);
                    using var integrity = backup.CreateCommand();
                    integrity.CommandText = "PRAGMA integrity_check;";
                    if (!string.Equals(integrity.ExecuteScalar()?.ToString(), "ok", StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Legacy quarantine backup failed SQLite integrity verification.");
                    using var backedUpRows = backup.CreateCommand();
                    backedUpRows.CommandText = "SELECT COALESCE(MAX(Id), 0) FROM QuarantineEntries;";
                    backedUpMaxId = Convert.ToInt64(backedUpRows.ExecuteScalar());
                }
                _logger?.LogInformation("Legacy quarantine metadata backed up before risk migration: {BackupFile}", backupName);
            }

            using var transaction = connection.BeginTransaction();
            using var recheck = connection.CreateCommand();
            recheck.Transaction = transaction;
            recheck.CommandText = "SELECT COUNT(1) FROM VaultMetadata WHERE Key = @Key;";
            recheck.Parameters.AddWithValue("@Key", migrationKey);
            if (Convert.ToInt64(recheck.ExecuteScalar()) != 0) return;

            using var normalize = connection.CreateCommand();
            normalize.Transaction = transaction;
            // Rows inserted after the snapshot have newer sequence IDs and must retain their
            // independently established risk; the backup could not restore those newer rows.
            normalize.CommandText = "UPDATE QuarantineEntries SET RiskLevel = @Unknown WHERE Id <= @BackedUpMaxId;";
            normalize.Parameters.AddWithValue("@Unknown", (int)RiskLevel.Unknown);
            normalize.Parameters.AddWithValue("@BackedUpMaxId", backedUpMaxId);
            int changed = normalize.ExecuteNonQuery();

            using var mark = connection.CreateCommand();
            mark.Transaction = transaction;
            mark.CommandText = "INSERT INTO VaultMetadata (Key, Value) VALUES (@Key, @Value);";
            mark.Parameters.AddWithValue("@Key", migrationKey);
            mark.Parameters.AddWithValue("@Value", backupName ?? "empty-vault");
            mark.ExecuteNonQuery();
            transaction.Commit();
            _logger?.LogInformation("Legacy quarantine risk labels marked Unknown for {Count} entries.", changed);
        }

        private void InitializeNextId()
        {
            using var connection = CreateConnection();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "UPDATE VaultSequence SET Value = MAX(Value, (SELECT COALESCE(MAX(Id), 0) FROM QuarantineEntries)) WHERE Id = 1;";
            cmd.ExecuteNonQuery();
        }

        public int AllocateNextId()
        {
            using var connection = CreateConnection();
            using var transaction = connection.BeginTransaction();
            using var cmd = connection.CreateCommand();
            cmd.Transaction = transaction;
            cmd.CommandText = "UPDATE VaultSequence SET Value = MAX(Value, (SELECT COALESCE(MAX(Id), 0) FROM QuarantineEntries)) + 1 WHERE Id = 1 RETURNING Value;";
            int id = checked(Convert.ToInt32(cmd.ExecuteScalar()));
            transaction.Commit();
            return id;
        }

        public SemaphoreSlim GetPathLock(string canonicalPath)
        {
            return _pathLocks.GetOrAdd(canonicalPath, _ => new SemaphoreSlim(1, 1));
        }

        public SemaphoreSlim GetHashLock(string sha256)
        {
            return _hashLocks.GetOrAdd(sha256, _ => new SemaphoreSlim(1, 1));
        }

        public async Task InsertEntryAsync(QuarantineEntry entry, string canonicalPath, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Reject a structurally invalid index before committing anything. After commit,
            // SQLite is authoritative: a failed compatibility mirror must not undo the vault.
            if (Directory.Exists(_jsonIndexFilePath))
                throw new IOException("Index persistence failed: the index path is a directory.");

            lock (_syncLock)
            {
                using var connection = CreateConnection();
                using var transaction = connection.BeginTransaction();
                try
                {
                    using var cmd = connection.CreateCommand();
                    cmd.Transaction = transaction;
                    cmd.CommandText = @"
                        INSERT INTO QuarantineEntries (
                            Id, OriginalPath, CanonicalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status, OwnerSid
                        ) VALUES (
                            @Id, @OriginalPath, @CanonicalPath, @QuarantinePath, @FileName, @SHA256, @FileSize, @Reason, @RiskLevel, @QuarantinedAt, @RestoredAt, @Status, @OwnerSid
                        );
                    ";

                    cmd.Parameters.AddWithValue("@Id", entry.Id);
                    cmd.Parameters.AddWithValue("@OriginalPath", entry.OriginalPath);
                    cmd.Parameters.AddWithValue("@CanonicalPath", canonicalPath);
                    cmd.Parameters.AddWithValue("@QuarantinePath", entry.QuarantinePath);
                    cmd.Parameters.AddWithValue("@FileName", entry.FileName);
                    cmd.Parameters.AddWithValue("@SHA256", entry.SHA256);
                    cmd.Parameters.AddWithValue("@FileSize", entry.FileSize);
                    cmd.Parameters.AddWithValue("@Reason", entry.Reason ?? string.Empty);
                    cmd.Parameters.AddWithValue("@RiskLevel", (int)entry.RiskLevel);
                    cmd.Parameters.AddWithValue("@QuarantinedAt", entry.QuarantinedAt.ToString("o"));
                    cmd.Parameters.AddWithValue("@RestoredAt", entry.RestoredAt.HasValue ? (object)entry.RestoredAt.Value.ToString("o") : DBNull.Value);
                    cmd.Parameters.AddWithValue("@Status", (int)entry.Status);
                    cmd.Parameters.AddWithValue("@OwnerSid", entry.OwnerSid is null ? DBNull.Value : entry.OwnerSid);

                    cmd.ExecuteNonQuery();
                    transaction.Commit();
                }
                catch
                {
                    transaction.Rollback();
                    throw;
                }

                SyncJsonMirror();
            }

            await Task.CompletedTask;
        }

        public async Task UpdateStatusAsync(int id, QuarantineStatus status, DateTime? restoredAt = null, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            lock (_syncLock)
            {
                using var connection = CreateConnection();
                using var transaction = connection.BeginTransaction();
                try
                {
                    using var cmd = connection.CreateCommand();
                    cmd.Transaction = transaction;
                    cmd.CommandText = @"
                        UPDATE QuarantineEntries
                        SET Status = @Status,
                            RestoredAt = @RestoredAt
                        WHERE Id = @Id;
                    ";
                    cmd.Parameters.AddWithValue("@Id", id);
                    cmd.Parameters.AddWithValue("@Status", (int)status);
                    cmd.Parameters.AddWithValue("@RestoredAt", restoredAt.HasValue ? (object)restoredAt.Value.ToString("o") : DBNull.Value);

                    cmd.ExecuteNonQuery();
                    transaction.Commit();
                }
                catch
                {
                    transaction.Rollback();
                    throw;
                }

                SyncJsonMirror();
            }

            await Task.CompletedTask;
        }

        public async Task RemoveEntryAsync(int id, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            lock (_syncLock)
            {
                using var connection = CreateConnection();
                using var transaction = connection.BeginTransaction();
                try
                {
                    using var cmd = connection.CreateCommand();
                    cmd.Transaction = transaction;
                    cmd.CommandText = "DELETE FROM QuarantineEntries WHERE Id = @Id;";
                    cmd.Parameters.AddWithValue("@Id", id);
                    cmd.ExecuteNonQuery();
                    transaction.Commit();
                }
                catch
                {
                    transaction.Rollback();
                    throw;
                }

                SyncJsonMirror();
            }

            await Task.CompletedTask;
        }

        public Task<List<QuarantineEntry>> GetAllEntriesAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var list = new List<QuarantineEntry>();

            lock (_syncLock)
            {
                using var connection = CreateConnection();
                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT Id, OriginalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status, OwnerSid
                    FROM QuarantineEntries
                    ORDER BY Id ASC;
                ";

                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    list.Add(MapReaderToEntry(reader));
                }
            }

            return Task.FromResult(list);
        }

        public Task<List<QuarantineEntry>> GetActiveQuarantinedAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var list = new List<QuarantineEntry>();

            lock (_syncLock)
            {
                using var connection = CreateConnection();
                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT Id, OriginalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status, OwnerSid
                    FROM QuarantineEntries
                    WHERE Status = @Status
                    ORDER BY QuarantinedAt DESC;
                ";
                cmd.Parameters.AddWithValue("@Status", (int)QuarantineStatus.Quarantined);

                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    list.Add(MapReaderToEntry(reader));
                }
            }

            return Task.FromResult(list);
        }

        public Task<QuarantineEntry?> GetEntryByIdAsync(int id, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            lock (_syncLock)
            {
                using var connection = CreateConnection();
                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT Id, OriginalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status, OwnerSid
                    FROM QuarantineEntries
                    WHERE Id = @Id;
                ";
                cmd.Parameters.AddWithValue("@Id", id);

                using var reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    return Task.FromResult<QuarantineEntry?>(MapReaderToEntry(reader));
                }
            }

            return Task.FromResult<QuarantineEntry?>(null);
        }

        public Task<List<QuarantineEntry>> GetEntriesByHashAsync(string sha256, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var list = new List<QuarantineEntry>();

            lock (_syncLock)
            {
                using var connection = CreateConnection();
                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT Id, OriginalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status, OwnerSid
                    FROM QuarantineEntries
                    WHERE LOWER(SHA256) = LOWER(@SHA256);
                ";
                cmd.Parameters.AddWithValue("@SHA256", sha256);

                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    list.Add(MapReaderToEntry(reader));
                }
            }

            return Task.FromResult(list);
        }

        private QuarantineEntry MapReaderToEntry(SqliteDataReader reader)
        {
            return new QuarantineEntry
            {
                Id = reader.GetInt32(0),
                OriginalPath = reader.GetString(1),
                QuarantinePath = reader.GetString(2),
                FileName = reader.GetString(3),
                SHA256 = reader.GetString(4),
                FileSize = reader.GetInt64(5),
                Reason = reader.IsDBNull(6) ? string.Empty : reader.GetString(6),
                RiskLevel = _riskMigrationApplied ? (RiskLevel)reader.GetInt32(7) : RiskLevel.Unknown,
                QuarantinedAt = DateTime.TryParse(reader.GetString(8), out var qAt) ? qAt : DateTime.UtcNow,
                RestoredAt = reader.IsDBNull(9) ? null : (DateTime.TryParse(reader.GetString(9), out var rAt) ? rAt : null),
                Status = (QuarantineStatus)reader.GetInt32(10),
                OwnerSid = reader.IsDBNull(11) ? null : reader.GetString(11)
            };
        }


        public void Dispose()
        {
            // Connections are scoped and pooling is disabled. Do not interrupt other vaults
            // or force a process-wide GC when this instance is disposed.
        }
    }
}
