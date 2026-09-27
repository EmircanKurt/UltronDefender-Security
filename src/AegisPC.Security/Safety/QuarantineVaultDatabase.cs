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
    public class QuarantineVaultDatabase : IDisposable
    {
        private readonly string _vaultDir;
        private readonly string _dbPath;
        private readonly string _connectionString;
        private readonly string _jsonIndexFilePath;
        private readonly ILogger? _logger;
        private readonly object _syncLock = new();

        // Eşzamanlı işlemlerde yarış durumlarını ve mükerrer karantinayı engelleyen eşzamanlı kilit haritası
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> _pathLocks = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> _hashLocks = new(StringComparer.OrdinalIgnoreCase);

        public QuarantineVaultDatabase(string vaultDir, ILogger? logger = null)
        {
            _vaultDir = vaultDir;
            _logger = logger;
            _dbPath = Path.Combine(vaultDir, "QuarantineVault.db");
            _connectionString = new SqliteConnectionStringBuilder { DataSource = _dbPath, Pooling = false }.ToString();
            _jsonIndexFilePath = Path.Combine(vaultDir, "quarantine_index.json");

            Directory.CreateDirectory(_vaultDir);
            InitializeDatabase();
            MigrateLegacyJsonIndex();
            InitializeNextId();
            if (File.Exists(_jsonIndexFilePath) || GetAllEntriesAsync().GetAwaiter().GetResult().Count > 0)
            {
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
                    Status INTEGER NOT NULL
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
                            Id, OriginalPath, CanonicalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status
                        ) VALUES (
                            @Id, @OriginalPath, @CanonicalPath, @QuarantinePath, @FileName, @SHA256, @FileSize, @Reason, @RiskLevel, @QuarantinedAt, @RestoredAt, @Status
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
                    SELECT Id, OriginalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status
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
                    SELECT Id, OriginalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status
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
                    SELECT Id, OriginalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status
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
                    SELECT Id, OriginalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status
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

        private static QuarantineEntry MapReaderToEntry(SqliteDataReader reader)
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
                RiskLevel = (RiskLevel)reader.GetInt32(7),
                QuarantinedAt = DateTime.TryParse(reader.GetString(8), out var qAt) ? qAt : DateTime.UtcNow,
                RestoredAt = reader.IsDBNull(9) ? null : (DateTime.TryParse(reader.GetString(9), out var rAt) ? rAt : null),
                Status = (QuarantineStatus)reader.GetInt32(10)
            };
        }

        /// <summary>
        /// Eski quarantine_index.json dosyasını SQLite'a aktarır ve dosyayı güvenle arşivler.
        /// </summary>
        private void MigrateLegacyJsonIndex()
        {
            try
            {
                if (!File.Exists(_jsonIndexFilePath)) return;
                using var connection = CreateConnection();
                using var transaction = connection.BeginTransaction();
                using var marker = connection.CreateCommand();
                marker.Transaction = transaction;
                marker.CommandText = "SELECT COUNT(1) FROM VaultMetadata WHERE Key = 'LegacyJsonMigration';";
                if (Convert.ToInt64(marker.ExecuteScalar()) > 0) return;

                string json = File.ReadAllText(_jsonIndexFilePath);
                if (string.IsNullOrWhiteSpace(json)) return;

                var legacyEntries = JsonSerializer.Deserialize<List<QuarantineEntry>>(json);
                if (legacyEntries == null || legacyEntries.Count == 0) return;
                // Preserve the untouched input before remapping colliding IDs.
                if (!File.Exists(_jsonIndexFilePath + ".migration-backup"))
                    File.Copy(_jsonIndexFilePath, _jsonIndexFilePath + ".migration-backup", overwrite: false);

                using var maxCmd = connection.CreateCommand();
                maxCmd.Transaction = transaction;
                maxCmd.CommandText = "SELECT COALESCE(MAX(Id), 0) FROM QuarantineEntries;";
                int nextLegacyId = Math.Max(Convert.ToInt32(maxCmd.ExecuteScalar()), legacyEntries.Max(e => e.Id));

                foreach (var entry in legacyEntries)
                {
                    using var checkCmd = connection.CreateCommand();
                    checkCmd.Transaction = transaction;
                    checkCmd.CommandText = "SELECT COUNT(1) FROM QuarantineEntries WHERE QuarantinePath = @Path AND OriginalPath = @Original AND SHA256 = @Hash;";
                    checkCmd.Parameters.AddWithValue("@Path", entry.QuarantinePath ?? string.Empty);
                    checkCmd.Parameters.AddWithValue("@Original", entry.OriginalPath ?? string.Empty);
                    checkCmd.Parameters.AddWithValue("@Hash", entry.SHA256 ?? string.Empty);
                    checkCmd.Parameters.AddWithValue("@Id", entry.Id);
                    long exists = (long)(checkCmd.ExecuteScalar() ?? 0L);

                    if (exists == 0)
                    {
                        checkCmd.CommandText = "SELECT COUNT(1) FROM QuarantineEntries WHERE Id = @Id;";
                        if (entry.Id <= 0 || Convert.ToInt64(checkCmd.ExecuteScalar()) > 0)
                            entry.Id = checked(++nextLegacyId);
                        using var insertCmd = connection.CreateCommand();
                        insertCmd.Transaction = transaction;
                        insertCmd.CommandText = @"
                            INSERT INTO QuarantineEntries (
                                Id, OriginalPath, CanonicalPath, QuarantinePath, FileName, SHA256, FileSize, Reason, RiskLevel, QuarantinedAt, RestoredAt, Status
                            ) VALUES (
                                @Id, @OriginalPath, @CanonicalPath, @QuarantinePath, @FileName, @SHA256, @FileSize, @Reason, @RiskLevel, @QuarantinedAt, @RestoredAt, @Status
                            );
                        ";
                        insertCmd.Parameters.AddWithValue("@Id", entry.Id);
                        insertCmd.Parameters.AddWithValue("@OriginalPath", entry.OriginalPath ?? string.Empty);
                        insertCmd.Parameters.AddWithValue("@CanonicalPath", entry.OriginalPath ?? string.Empty);
                        insertCmd.Parameters.AddWithValue("@QuarantinePath", entry.QuarantinePath ?? string.Empty);
                        insertCmd.Parameters.AddWithValue("@FileName", entry.FileName ?? Path.GetFileName(entry.OriginalPath) ?? "unknown");
                        insertCmd.Parameters.AddWithValue("@SHA256", entry.SHA256 ?? string.Empty);
                        insertCmd.Parameters.AddWithValue("@FileSize", entry.FileSize);
                        insertCmd.Parameters.AddWithValue("@Reason", entry.Reason ?? string.Empty);
                        insertCmd.Parameters.AddWithValue("@RiskLevel", (int)entry.RiskLevel);
                        insertCmd.Parameters.AddWithValue("@QuarantinedAt", entry.QuarantinedAt.ToString("o"));
                        insertCmd.Parameters.AddWithValue("@RestoredAt", entry.RestoredAt.HasValue ? (object)entry.RestoredAt.Value.ToString("o") : DBNull.Value);
                        insertCmd.Parameters.AddWithValue("@Status", (int)entry.Status);
                        insertCmd.ExecuteNonQuery();
                    }
                }

                marker.CommandText = "INSERT INTO VaultMetadata (Key, Value) VALUES ('LegacyJsonMigration', '1');";
                marker.ExecuteNonQuery();
                transaction.Commit();

                // Arşivleme: Eski JSON dosyasını güvenle yedekle
                string backupPath = _jsonIndexFilePath + ".migrated";
                try
                {
                    if (!File.Exists(backupPath)) File.Copy(_jsonIndexFilePath, backupPath, overwrite: false);
                }
                catch { }

                _logger?.LogInformation("Legacy quarantine index migrated successfully to SQLite ({Count} entries).", legacyEntries.Count);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to migrate legacy quarantine_index.json to SQLite; original index preserved.");
                throw;
            }
        }

        /// <summary>
        /// Geriye dönük uyumluluk ve testlerin JSON okuması için SQLite içeriğini quarantine_index.json ile senkronize eder.
        /// </summary>
        public void SyncJsonMirror()
        {
            try
            {
                var entries = GetAllEntriesAsync().GetAwaiter().GetResult();
                string json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
                string tmpPath = _jsonIndexFilePath + "." + Guid.NewGuid().ToString("N") + ".sync.tmp";
                File.WriteAllText(tmpPath, json);
                File.Move(tmpPath, _jsonIndexFilePath, overwrite: true);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Could not sync compatibility index; SQLite remains authoritative.");
            }
        }

        /// <summary>
        /// Başlangıçta yarım kalan geçici dosyaları (.tmp) temizler ve veritabanı tutarlılığını sağlar.
        /// </summary>
        private void ReconcileIncompleteTransactions()
        {
            try
            {
                if (!Directory.Exists(_vaultDir)) return;

                var tempFiles = Directory.GetFiles(_vaultDir, "*.tmp", SearchOption.TopDirectoryOnly);
                foreach (var tmp in tempFiles)
                {
                    try
                    {
                        File.Delete(tmp);
                        _logger?.LogInformation("Cleaned incomplete quarantine temporary file: {File}", tmp);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning(ex, "Failed to clean temporary quarantine file: {File}", tmp);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed during quarantine reconciliation.");
            }
        }

        public void Dispose()
        {
            // Connections are scoped and pooling is disabled. Do not interrupt other vaults
            // or force a process-wide GC when this instance is disposed.
        }
    }
}
