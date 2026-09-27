using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Safety
{
    /// <summary>
    /// Persists explicitly selected exclusions in SQLite and evaluates an atomic process-local snapshot.
    /// A trusted IPC owner must refresh this snapshot when another process changes the shared store.
    /// </summary>
    public class ExclusionService : IExclusionService, IExclusionRefreshService
    {
        private readonly IDatabaseService _databaseService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger<ExclusionService>? _logger;

        private ExclusionSnapshot _snapshot = ExclusionSnapshot.Empty;
        private readonly ConcurrentDictionary<string, (DateTime ExpiryUtc, string? Reason)> _temporaryPathExclusions = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, (string Sha256, DateTime ExpiryUtc)> _temporaryContentExclusions = new(StringComparer.OrdinalIgnoreCase);

        private readonly SemaphoreSlim _initLock = new(1, 1);
        private volatile bool _isInitialized;

        /// <summary>Creates a store-bound exclusion manager; it does not read or modify the database until requested.</summary>
        public ExclusionService(
            IDatabaseService databaseService,
            IAuditLogService? auditLogService = null,
            ILogger<ExclusionService>? logger = null)
        {
            _databaseService = databaseService ?? throw new ArgumentNullException(nameof(databaseService));
            _auditLogService = auditLogService;
            _logger = logger;
        }

        /// <summary>Loads persisted rules once; database failures and cancellation propagate without publishing a partial snapshot.</summary>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            if (_isInitialized) return;

            await _initLock.WaitAsync(cancellationToken);
            try
            {
                if (_isInitialized) return;

                await ReadAndPublishSnapshotAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to initialize ExclusionService from SQLite database.");
                throw;
            }
            finally
            {
                _initLock.Release();
            }
        }

        /// <summary>Reloads committed exclusions atomically; failed reads retain the previous snapshot and propagate the error.</summary>
        public async Task ReloadAsync(CancellationToken cancellationToken = default)
        {
            await _initLock.WaitAsync(cancellationToken);
            try { await ReadAndPublishSnapshotAsync(cancellationToken); }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Exclusion refresh failed; the previous snapshot remains active.");
                throw;
            }
            finally { _initLock.Release(); }
        }

        private async Task ReadAndPublishSnapshotAsync(CancellationToken cancellationToken)
        {
            var entries = new List<ExclusionEntry>();
            using var conn = await OpenConnectionAsync(cancellationToken);
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT Id, Type, Value, AddedUtc, Reason, IncludeSubdirectories FROM Exclusions;";
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var entry = new ExclusionEntry
                {
                    Id = reader.GetInt32(0), Type = (ExclusionType)reader.GetInt32(1), Value = reader.GetString(2),
                    AddedUtc = DateTime.TryParse(reader.GetString(3), out var date) ? date : DateTime.UtcNow,
                    Reason = reader.IsDBNull(4) ? null : reader.GetString(4), IncludeSubdirectories = reader.GetInt32(5) != 0
                };
                if (!Enum.IsDefined(entry.Type) || string.IsNullOrWhiteSpace(entry.Value))
                    throw new InvalidDataException("Persisted exclusion contains an invalid type or value.");
                entry.Value = entry.Type == ExclusionType.Sha256 ? entry.Value.Trim().ToUpperInvariant() : NormalizePath(entry.Value);
                if (entry.Type == ExclusionType.Sha256 && !IsValidHash(entry.Value))
                    throw new InvalidDataException("Persisted exclusion contains an invalid SHA-256 hash.");
                if (entry.Type == ExclusionType.Path && IsRootOrSystemDirectory(entry.Value))
                    throw new InvalidDataException("Persisted exclusion covers a protected root directory.");
                entries.Add(entry);
            }
            cancellationToken.ThrowIfCancellationRequested();
            PublishSnapshot(entries);
            _isInitialized = true;
            _logger?.LogInformation("Exclusion snapshot loaded with {Count} entries.", entries.Count);
        }

        private void PublishSnapshot(IEnumerable<ExclusionEntry> entries)
        {
            Volatile.Write(ref _snapshot, new ExclusionSnapshot(entries, NormalizePath));
            DetectionPolicyRevision.Invalidate();
        }

        private static bool IsValidHash(string hash) => hash.Length == 64 && hash.All(Uri.IsHexDigit);

        private void EnsureInitialized()
        {
            if (!_isInitialized)
            {
                InitializeAsync().GetAwaiter().GetResult();
            }
        }

        private void IndexEntryInMemory(ExclusionEntry entry)
        {
            PublishSnapshot(Volatile.Read(ref _snapshot).Entries.Values.Append(entry));
        }

        private void RemoveEntryFromMemory(ExclusionEntry entry)
        {
            PublishSnapshot(Volatile.Read(ref _snapshot).Entries.Values.Where(existing => existing.Id != entry.Id));
        }

        private static string NormalizePath(string path)
        {
            var full = Path.GetFullPath(path);
            var root = Path.GetPathRoot(full);
            if (!string.IsNullOrEmpty(root) && string.Equals(full.TrimEnd('\\', '/'), root.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
            {
                return root;
            }
            return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        /// <summary>Checks the current snapshot without disk I/O after initialization; malformed paths cannot match an exclusion.</summary>
        public bool IsExcluded(string? filePath, string? sha256 = null)
        {
            EnsureInitialized();
            var snapshot = Volatile.Read(ref _snapshot);

            // 1. SHA-256 Hash Kontrolü (O(1))
            if (!string.IsNullOrEmpty(sha256))
            {
                var cleanHash = sha256.Trim().ToUpperInvariant();
                if (snapshot.Hashes.ContainsKey(cleanHash))
                {
                    return true;
                }
            }

            // 2. Yol Kontrolü
            if (string.IsNullOrWhiteSpace(filePath))
            {
                return false;
            }

            string normalizedPath;
            try { normalizedPath = NormalizePath(filePath); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                _logger?.LogDebug(ex, "Invalid path cannot match an exclusion: {Path}", filePath);
                return false;
            }
            if (_temporaryContentExclusions.TryGetValue(normalizedPath, out var contentEx))
            {
                if (DateTime.UtcNow > contentEx.ExpiryUtc)
                    _temporaryContentExclusions.TryRemove(normalizedPath, out _);
                else if (!string.IsNullOrWhiteSpace(sha256) && string.Equals(contentEx.Sha256, sha256, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // 2a. Geçici Yol İstisnaları (Geri yükleme / Restore istisnası vb. - O(1))
            if (_temporaryPathExclusions.TryGetValue(normalizedPath, out var tempEx))
            {
                if (DateTime.UtcNow <= tempEx.ExpiryUtc)
                {
                    return true;
                }
                _temporaryPathExclusions.TryRemove(normalizedPath, out _);
            }

            // 2b. Doğrudan dosya veya klasör yolu tam eşleşmesi (O(1))
            if (snapshot.Paths.ContainsKey(normalizedPath))
            {
                return true;
            }

            // 2c. Klasör önek ağacı / Parent Walk (O(depth))
            var currentDir = Path.GetDirectoryName(normalizedPath);
            bool isDirectChild = true;

            while (!string.IsNullOrEmpty(currentDir))
            {
                var trimmedDir = currentDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                if (_temporaryPathExclusions.TryGetValue(trimmedDir, out var tempDirEx))
                {
                    if (DateTime.UtcNow <= tempDirEx.ExpiryUtc)
                    {
                        return true;
                    }
                    _temporaryPathExclusions.TryRemove(trimmedDir, out _);
                }

                if (snapshot.Folders.TryGetValue(trimmedDir, out var folderEntry))
                {
                    if (folderEntry.IncludeSubdirectories || isDirectChild)
                    {
                        return true;
                    }
                }

                isDirectChild = false;
                var parent = Path.GetDirectoryName(trimmedDir);
                if (string.Equals(parent, currentDir, StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }
                currentDir = parent;
            }

            return false;
        }

        /// <summary>Initializes cancellably and checks explicit hash/path rules; it does not treat an absent rule as verified safety.</summary>
        public async Task<bool> IsExcludedAsync(string? filePath, string? sha256 = null, CancellationToken cancellationToken = default)
        {
            await InitializeAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return IsExcluded(filePath, sha256);
        }

        /// <summary>Returns detached display copies so caller edits cannot alter active rules or prevent their removal.</summary>
        public async Task<IReadOnlyList<ExclusionEntry>> GetAllExclusionsAsync(CancellationToken cancellationToken = default)
        {
            await InitializeAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return Volatile.Read(ref _snapshot).Entries.Values.OrderByDescending(e => e.AddedUtc).Select(ExclusionSnapshot.CopyEntry).ToList();
        }

        /// <summary>Rejects whole-volume and standard operating-system/application roots before any explicit path exemption can be persisted.</summary>
        public bool IsRootOrSystemDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;

            try
            {
                // Sürücü harfi formatı doğrudan kontrol (örn. C:, C:\, D:, D:\)
                var trimmedRaw = path.Trim().TrimEnd('\\', '/');
                if (trimmedRaw.Length == 2 && trimmedRaw[1] == ':')
                {
                    return true;
                }

                var full = Path.GetFullPath(path);
                var root = Path.GetPathRoot(full);

                // Kök sürücü kontrolü (örn. C:\, D:\)
                if (!string.IsNullOrEmpty(root) && string.Equals(full.TrimEnd('\\', '/'), root.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                var norm = full.TrimEnd('\\', '/');

                // Windows sistem dizinleri
                var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (!string.IsNullOrEmpty(winDir) && string.Equals(norm, winDir.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                var sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                if (!string.IsNullOrEmpty(sysDir) && string.Equals(norm, sysDir.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                var progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                if (!string.IsNullOrEmpty(progFiles) && string.Equals(norm, progFiles.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                var progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                if (!string.IsNullOrEmpty(progFilesX86) && string.Equals(norm, progFilesX86.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                var progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                if (!string.IsNullOrEmpty(progData) && string.Equals(norm, progData.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Error validating system directory for path: {Path}", path);
            }

            return false;
        }

        /// <summary>Persists an explicit path rule after protected-root validation; mutations serialize with refreshes and invalidate cached decisions.</summary>
        public async Task<ExclusionEntry> AddPathExclusionAsync(
            string path,
            bool includeSubdirectories = true,
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("İstisna yolu boş olamaz.", nameof(path));
            }

            if (IsRootOrSystemDirectory(path))
            {
                throw new InvalidOperationException("Kritik sistem dizinlerinin (C:\\, Windows, Program Files vb.) kökten istisna yapılması güvenlik gerekçesiyle engellenmiştir.");
            }

            var normalized = NormalizePath(path);

            if (IsRootOrSystemDirectory(normalized))
            {
                throw new InvalidOperationException("Kritik sistem dizinlerinin (C:\\, Windows, Program Files vb.) kökten istisna yapılması güvenlik gerekçesiyle engellenmiştir.");
            }

            var entry = new ExclusionEntry
            {
                Type = ExclusionType.Path,
                Value = normalized,
                AddedUtc = DateTime.UtcNow,
                Reason = reason ?? "Kullanıcı tanımlı yol istisnası",
                IncludeSubdirectories = includeSubdirectories
            };

            await PersistEntryAsync(entry, cancellationToken);

            await ExclusionAuditWriter.RecordAsync(_auditLogService, _logger, AuditAction.ExclusionAdded, entry,
                $"Path exclusion added (recursive: {includeSubdirectories}). Reason: {entry.Reason}", cancellationToken);

            _logger?.LogInformation("Added path exclusion: {Path} (Recursive: {Sub})", entry.Value, includeSubdirectories);
            return entry;
        }

        /// <summary>Persists an explicit content-bound rule only for a valid 64-character hexadecimal SHA-256 value.</summary>
        public async Task<ExclusionEntry> AddSha256ExclusionAsync(
            string sha256,
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(sha256))
            {
                throw new ArgumentException("SHA-256 hash boş olamaz.", nameof(sha256));
            }

            var cleanHash = sha256.Trim().ToUpperInvariant();
            if (!IsValidHash(cleanHash))
            {
                throw new ArgumentException("SHA-256 değeri 64 onaltılık karakter içermelidir.", nameof(sha256));
            }

            var entry = new ExclusionEntry
            {
                Type = ExclusionType.Sha256,
                Value = cleanHash,
                AddedUtc = DateTime.UtcNow,
                Reason = reason ?? "Kullanıcı tanımlı hash istisnası",
                IncludeSubdirectories = false
            };

            await PersistEntryAsync(entry, cancellationToken);

            await ExclusionAuditWriter.RecordAsync(_auditLogService, _logger, AuditAction.ExclusionAdded, entry,
                $"SHA-256 exclusion added. Reason: {entry.Reason}", cancellationToken);

            _logger?.LogInformation("Added SHA-256 exclusion: {Hash}", cleanHash);
            return entry;
        }

        private async Task PersistEntryAsync(ExclusionEntry entry, CancellationToken cancellationToken)
        {
            await InitializeAsync(cancellationToken);
            await _initLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);
                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    INSERT INTO Exclusions (Type, Value, AddedUtc, Reason, IncludeSubdirectories)
                    VALUES (@type, @val, @added, @reason, @sub);
                    SELECT last_insert_rowid();";
                AddParameter(cmd, "@type", (int)entry.Type);
                AddParameter(cmd, "@val", entry.Value);
                AddParameter(cmd, "@added", entry.AddedUtc.ToString("o"));
                AddParameter(cmd, "@reason", entry.Reason);
                AddParameter(cmd, "@sub", entry.IncludeSubdirectories ? 1 : 0);
                entry.Id = Convert.ToInt32(await cmd.ExecuteScalarAsync(cancellationToken));
                IndexEntryInMemory(entry);
            }
            finally { _initLock.Release(); }
        }

        /// <summary>Adds an explicitly requested temporary path rule; broad path rules remain distinct from content-bound restore exemptions.</summary>
        public void AddTemporaryPathExclusion(string path, TimeSpan duration, string? reason = null)
        {
            if (string.IsNullOrWhiteSpace(path)) return;

            var normalized = NormalizePath(path);
            var expiry = DateTime.UtcNow.Add(duration);
            _temporaryPathExclusions[normalized] = (expiry, reason);
            DetectionPolicyRevision.Invalidate();
            _logger?.LogInformation("Temporary path exclusion added for {Path}, lasting {Minutes} minutes until {ExpiryUtc}. Reason: {Reason}",
                normalized, duration.TotalMinutes, expiry, reason ?? "Geri yükleme");
        }

        /// <summary>Temporarily exempts only the exact restored content; path replacements or missing fingerprints do not match.</summary>
        public void AddTemporaryContentExclusion(string path, string sha256, TimeSpan duration, string? reason = null)
        {
            if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(sha256) || !IsValidHash(sha256) || duration <= TimeSpan.Zero)
                return;
            _temporaryContentExclusions[NormalizePath(path)] = (sha256, DateTime.UtcNow.Add(duration));
            DetectionPolicyRevision.Invalidate();
        }

        /// <summary>Removes a persisted rule and republishes the remaining coverage, including duplicate rules sharing the same normalized value.</summary>
        public async Task<bool> RemoveExclusionAsync(int id, CancellationToken cancellationToken = default)
        {
            await InitializeAsync(cancellationToken);
            await _initLock.WaitAsync(cancellationToken);
            ExclusionEntry entry;
            bool removed;
            try
            {
                if (!Volatile.Read(ref _snapshot).Entries.TryGetValue(id, out var storedEntry)) return false;
                entry = storedEntry;
                using var conn = await OpenConnectionAsync(cancellationToken);
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM Exclusions WHERE Id = @id;";
                AddParameter(cmd, "@id", id);
                removed = await cmd.ExecuteNonQueryAsync(cancellationToken) > 0;
                RemoveEntryFromMemory(entry);
            }
            finally { _initLock.Release(); }
            if (!removed) return false;

            await ExclusionAuditWriter.RecordAsync(_auditLogService, _logger, AuditAction.ExclusionRemoved, entry,
                $"Exclusion removed (type: {entry.Type}).", cancellationToken);

            _logger?.LogInformation("Removed exclusion: {Value} (Id: {Id})", entry.Value, id);
            return true;
        }

        private async Task<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken)
        {
            var conn = _databaseService.CreateConnection();
            try
            {
                if (conn.State != ConnectionState.Open) await conn.OpenAsync(cancellationToken);
                return conn;
            }
            catch
            {
                await conn.DisposeAsync();
                throw;
            }
        }

        private static void AddParameter(DbCommand cmd, string name, object? value)
        {
            var param = cmd.CreateParameter();
            param.ParameterName = name;
            param.Value = value ?? DBNull.Value;
            cmd.Parameters.Add(param);
        }
    }
}
