using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Safety;

/// <summary>Separates recovery and compatibility persistence from the containment transaction.</summary>
public partial class QuarantineVaultDatabase
{
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
                        // Legacy JSON carried only display-text-derived risk, never trusted evidence.
                        insertCmd.Parameters.AddWithValue("@RiskLevel", (int)RiskLevel.Unknown);
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
}
