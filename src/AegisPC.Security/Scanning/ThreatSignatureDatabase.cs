using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Data.Sqlite;
using Serilog;
using AegisPC.Contracts.ThreatIntelligence;
using AegisPC.Security.ThreatIntelligence;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Genişletilebilir yerel tehdit imzası veritabanı (SQLite + InMemory Fast Cache).
    /// Retains legacy/imported metadata for review. SQLite labels/checksums are not provenance.
    /// Exact detection uses the same authenticated catalogue as manual and real-time scanning.
    /// </summary>
    public static class ThreatSignatureDatabase
    {
        private static readonly object _initLock = new();
        private static bool _isInitialized = false;
        private static string _dbPath = string.Empty;
        private static readonly ConcurrentDictionary<string, (string Name, string Category, int Severity)> _memoryCache = new(StringComparer.OrdinalIgnoreCase);

        public static int TotalSignaturesCount => AuthoritativeThreatCatalog.Count;
        public static int UnverifiedMetadataCount => _memoryCache.Count;
        public static DateTime LastDatabaseUpdate { get; private set; } = DateTime.Now;
        public static string CurrentDbPath => _dbPath;

        public static void ResetForTesting(string? customDbPath = null)
        {
            lock (_initLock)
            {
                SqliteConnection.ClearAllPools();
                _isInitialized = false;
                _memoryCache.Clear();
                _dbPath = string.Empty;
                if (!string.IsNullOrEmpty(customDbPath))
                {
                    Initialize(customDbPath);
                }
            }
        }

        public static DateTime GetLastDatabaseUpdate()
        {
            try
            {
                if (!string.IsNullOrEmpty(_dbPath) && File.Exists(_dbPath))
                {
                    var fileTime = File.GetLastWriteTime(_dbPath);
                    if (fileTime > LastDatabaseUpdate)
                    {
                        LastDatabaseUpdate = fileTime;
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Son veritabanı güncelleme zamanı alınırken hata oluştu.");
            }
            return LastDatabaseUpdate;
        }

        // Doğrulanmış test tehditleri — Yalnızca standart EICAR test imzaları tutulur.
        // Gerçek dünya tehdit imzaları dinamik olarak MalwareBazaar API üzerinden indirilir.
        private static readonly (string Sha256, string Name, string Category, int Severity)[] EmbeddedThreats = new[]
        {
            // --- TEST ZARARLILARI (EICAR) ---
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Standard-AV-Test-File", "TestMalware", 100),
            ("131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbcf18291", "EICAR-Standard-AV-Test-CRLF", "TestMalware", 100)
        };

        public static void Initialize(string? explicitDbPath = null)
        {
            if (_isInitialized && string.IsNullOrEmpty(explicitDbPath)) return;

            lock (_initLock)
            {
                if (_isInitialized && string.IsNullOrEmpty(explicitDbPath)) return;

                _memoryCache.Clear();
                // 1. Önce gömülü doğrulanmış EICAR tehditlerini önbelleğe yükle
                foreach (var threat in EmbeddedThreats)
                {
                    _memoryCache[threat.Sha256] = (threat.Name, threat.Category, threat.Severity);
                }

                if (!string.IsNullOrEmpty(explicitDbPath))
                {
                    _dbPath = explicitDbPath;
                    EnsureDatabaseIntegrity(_dbPath);
                    LoadAllSignaturesFromSqlite(_dbPath);
                    _isInitialized = true;
                    return;
                }

                bool initialized = false;

                // 2. ProgramData dizininde SQLite veritabanını ilklendir ve ACL sıkılaştır (yalnızca elevated ise)
                if (IsElevated())
                {
                    try
                    {
                        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                        string sigDir = Path.Combine(programData, "UltronDefender", "signatures");
                        if (!Directory.Exists(sigDir))
                        {
                            Directory.CreateDirectory(sigDir);
                        }

                        _dbPath = Path.Combine(sigDir, "threat_signatures.db");
                        EnsureDatabaseIntegrity(_dbPath);

                        // Sadece Administrators + SYSTEM yazabilir, Users okur
                        if (!TryTightenFileAcl(_dbPath))
                        {
                            throw new UnauthorizedAccessException("ProgramData signatures ACL sıkılaştırılamadı.");
                        }

                        LoadAllSignaturesFromSqlite(_dbPath);
                        initialized = true;
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "ProgramData altındaki tehdit veritabanı ilklendirilemedi veya ACL atanamadı. LocalApplicationData'ya düşülüyor.");
                    }
                }

                // 3. Fallback: LocalApplicationData (yetki yetersizse kullanıcı profiline düş)
                if (!initialized)
                {
                    try
                    {
                        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                        string sigDir = Path.Combine(localAppData, "UltronDefender", "signatures");
                        if (!Directory.Exists(sigDir))
                        {
                            Directory.CreateDirectory(sigDir);
                        }

                        _dbPath = Path.Combine(sigDir, "threat_signatures.db");
                        EnsureDatabaseIntegrity(_dbPath);
                        LoadAllSignaturesFromSqlite(_dbPath);
                        initialized = true;
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "LocalApplicationData tehdit veritabanı ilklendirilemedi. Yalnızca bellek içi doğrulanmış imzalar kullanılacak.");
                    }
                }

                _isInitialized = true;
            }
        }

        private static void LoadAllSignaturesFromSqlite(string dbPath)
        {
            if (string.IsNullOrEmpty(dbPath) || !File.Exists(dbPath)) return;
            try
            {
                using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadOnly");
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT Sha256, Name, Category, Severity FROM ThreatSignatures";
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    var sha = reader.GetString(0);
                    var name = reader.GetString(1);
                    var cat = reader.GetString(2);
                    var sev = reader.GetInt32(3);
                    if (Sha256Identity.IsValid(sha) && _memoryCache.Count < MaxMemoryCacheEntries)
                        _memoryCache.TryAdd(sha, (name, cat, sev));
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Tehdit imzaları SQLite'tan belleğe yüklenemedi: {DbPath}", dbPath);
            }
        }

        private static void EnsureDatabaseIntegrity(string dbPath)
        {
            string hashPath = dbPath + ".sha256";

            if (File.Exists(dbPath))
            {
                string currentHash = ComputeFileSha256(dbPath);

                if (File.Exists(hashPath))
                {
                    string expectedHash = File.ReadAllText(hashPath).Trim();

                    if (!string.Equals(expectedHash, currentHash, StringComparison.OrdinalIgnoreCase))
                    {
                        // A checksum is corruption detection, not publisher authentication.
                        Log.ForContext("SourceContext", "SECURITY").Error(
                            "Signature metadata checksum mismatch. Preserving a backup before schema reconciliation. Expected {ExpectedHash}, Actual {ActualHash}.",
                            expectedHash, currentHash);

                        InitSqliteDatabase(dbPath);
                        return;
                    }
                }
                else
                {
                    // Checksum dosyası yoksa veritabanını doğrula/temizle ve checksum oluştur
                    InitSqliteDatabase(dbPath);
                    return;
                }
            }
            else
            {
                InitSqliteDatabase(dbPath);
                return;
            }
            InitSqliteDatabase(dbPath);
        }

        private static void InitSqliteDatabase(string dbPath)
        {
            string? dir = Path.GetDirectoryName(dbPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            using (var conn = new SqliteConnection($"Data Source={dbPath}"))
            {
                conn.Open();
                // Consistent SQLite backup (includes committed WAL), before any legacy migration.
                using (var probe = conn.CreateCommand())
                {
                    probe.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ThreatSignatures'";
                    if (Convert.ToInt32(probe.ExecuteScalar()) > 0)
                    {
                        using var backup = new SqliteConnection($"Data Source={dbPath}.backup-{Guid.NewGuid():N};Pooling=False");
                        backup.Open();
                        conn.BackupDatabase(backup);
                    }
                }

                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS ThreatSignatures (
                        Sha256 TEXT PRIMARY KEY COLLATE NOCASE,
                        Name TEXT NOT NULL,
                        Category TEXT NOT NULL,
                        Severity INTEGER NOT NULL DEFAULT 100,
                        Source TEXT NOT NULL DEFAULT 'Embedded',
                        AddedUtc TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS IX_ThreatSignatures_Sha256 ON ThreatSignatures(Sha256);
                ";
                cmd.ExecuteNonQuery();

                using var trans = conn.BeginTransaction();
                var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                using (var schema = conn.CreateCommand())
                {
                    schema.Transaction = trans;
                    schema.CommandText = "PRAGMA table_info(ThreatSignatures)";
                    using var fields = schema.ExecuteReader();
                    while (fields.Read()) columns.Add(fields.GetString(1));
                }
                foreach (string column in new[] { "SourceReference", "PackageVersion", "VerificationStatus" })
                {
                    if (columns.Contains(column)) continue;
                    using var migration = conn.CreateCommand();
                    migration.Transaction = trans;
                    string defaultValue = column == "VerificationStatus" ? "'Unverified'" : "''";
                    migration.CommandText = $"ALTER TABLE ThreatSignatures ADD COLUMN {column} TEXT NOT NULL DEFAULT {defaultValue}";
                    migration.ExecuteNonQuery();
                }

                // Yalnızca doğrulanmış gömülü tehditleri (EICAR) ekle
                using var insertCmd = conn.CreateCommand();
                insertCmd.Transaction = trans;
                insertCmd.CommandText = @"
                    INSERT OR IGNORE INTO ThreatSignatures (Sha256, Name, Category, Severity, Source, AddedUtc)
                    VALUES ($sha256, $name, $category, $severity, 'Embedded', $addedUtc);
                ";

                var pSha = insertCmd.Parameters.Add("$sha256", SqliteType.Text);
                var pName = insertCmd.Parameters.Add("$name", SqliteType.Text);
                var pCat = insertCmd.Parameters.Add("$category", SqliteType.Text);
                var pSev = insertCmd.Parameters.Add("$severity", SqliteType.Integer);
                var pAdded = insertCmd.Parameters.Add("$addedUtc", SqliteType.Text);

                string nowIso = DateTime.UtcNow.ToString("o");
                foreach (var threat in EmbeddedThreats)
                {
                    pSha.Value = threat.Sha256;
                    pName.Value = threat.Name;
                    pCat.Value = threat.Category;
                    pSev.Value = threat.Severity;
                    pAdded.Value = nowIso;
                    insertCmd.ExecuteNonQuery();
                }

                trans.Commit();
            }

            // SqliteConnection kapandıktan sonra hash hesapla ve kaydet
            UpdateDatabaseChecksum(dbPath);
            if (dbPath.Contains("ProgramData", StringComparison.OrdinalIgnoreCase))
            {
                TryTightenFileAcl(dbPath);
                TryTightenFileAcl(dbPath + ".sha256");
            }
        }

        private static void UpdateDatabaseChecksum(string dbPath)
        {
            try
            {
                if (File.Exists(dbPath))
                {
                    string hash = ComputeFileSha256(dbPath);
                    string hashPath = dbPath + ".sha256";
                    File.WriteAllText(hashPath, hash);
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Tehdit veritabanı sağlama toplamı (checksum) güncellenemedi: {DbPath}", dbPath);
            }
        }

        public static string ComputeFileSha256(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] hashBytes = sha.ComputeHash(stream);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }

        public static bool TryTightenFileAcl(string filePath)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return true;
            if (!File.Exists(filePath)) return true;

            try
            {
                var fileInfo = new FileInfo(filePath);
                var fileSecurity = new FileSecurity();

                // Kalıtımı kaldırarak standart kullanıcıların yazma yetkilerini izole et
                fileSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                // LocalSystem (SYSTEM): FullControl
                fileSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));

                // Builtin Administrators (BA): FullControl
                fileSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));

                // Authenticated / Builtin Users: ReadOnly (ReadAndExecute | Synchronize)
                fileSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
                    AccessControlType.Allow));

                fileInfo.SetAccessControl(fileSecurity);
                return true;
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Dosya ACL sıkılaştırması uygulanamadı: {Path}", filePath);
                return false;
            }
        }

        private static bool IsElevated()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return false;
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(id);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Kullanıcı yetki kontrolü (elevation) yapılamadı.");
                return false;
            }
        }

        private const int MaxMemoryCacheEntries = 500000;

        private static void EnforceCacheLimit()
        {
            if (_memoryCache.Count > MaxMemoryCacheEntries)
            {
                int toRemove = MaxMemoryCacheEntries / 10; // En eski %10'u kaldır
                int removed = 0;
                foreach (var key in _memoryCache.Keys)
                {
                    if (removed >= toRemove) break;
                    _memoryCache.TryRemove(key, out _);
                    removed++;
                }
            }
        }

        /// <summary>
        /// O(1) hızında SHA-256 zararlı imza kontrolü — Saf bellek içi arama (sıfır disk SQLite gecikmesi).
        /// </summary>
        public static (bool IsMatched, string Name, string Category, int Severity) CheckHash(string sha256)
        {
            if (AuthoritativeThreatCatalog.TryGet(sha256, out var match) && match != null)
                return (true, match.ThreatName, match.Category, match.Severity);
            return (false, string.Empty, string.Empty, 0);
        }

        /// <summary>
        /// Checks an already loaded exact SHA-256 entry without initializing, reading, creating or modifying a database or ACL.
        /// Startup/feed ownership must load the store separately; this read-only gate cannot certify feed provenance.
        /// </summary>
        public static bool TryCheckLoadedHash(string? sha256, out (string Name, string Category, int Severity) match)
        {
            match = default;
            if (!AuthoritativeThreatCatalog.TryGet(sha256, out var verified) || verified == null) return false;
            match = (verified.ThreatName, verified.Category, verified.Severity);
            return true;
        }

        /// <summary>Read-only legacy lookup for audit; never a malware verdict or action authority.</summary>
        public static bool TryGetUnverifiedMetadata(string sha256, out (string Name, string Category, int Severity) metadata) =>
            _memoryCache.TryGetValue(sha256, out metadata);

        /// <summary>
        /// Retains unsigned source metadata for audit only. This import cannot activate detection hashes.
        /// </summary>
        public static int ImportThreatHashes(IEnumerable<(string Sha256, string Name, string Category, int Severity, string Source)> newThreats)
        {
            if (!_isInitialized) Initialize();
            if (string.IsNullOrEmpty(_dbPath) || !File.Exists(_dbPath)) return 0;

            var pendingThreats = new List<(string Sha256, string Name, string Category, int Severity, string Source)>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int visited = 0;
            foreach (var threat in newThreats)
            {
                if (++visited > SignedThreatIntelStore.MaxRecords) break;
                if (!Sha256Identity.IsValid(threat.Sha256))
                    continue;

                string normalizedHash = threat.Sha256.Trim().ToLowerInvariant();
                string source = threat.Source ?? "ThreatFeed";

                if (!string.Equals(source, "MalwareBazaar", StringComparison.OrdinalIgnoreCase))
                {
                    Log.Warning("Rejected non-MalwareBazaar threat import source {Source} for hash {Hash}.", source, normalizedHash);
                    continue;
                }

                if (_memoryCache.ContainsKey(normalizedHash) || !seen.Add(normalizedHash))
                {
                    continue;
                }

                string name = threat.Name ?? "Generic.Malware";
                string category = threat.Category ?? "Malware";
                int severity = Math.Clamp(threat.Severity, 1, 100);
                if (name.Length > 256 || category.Length > 80) continue;

                pendingThreats.Add((normalizedHash, name, category, severity, source));
            }

            if (pendingThreats.Count == 0)
            {
                return 0;
            }

            int imported = 0;
            try
            {
                using (var conn = new SqliteConnection($"Data Source={_dbPath}"))
                {
                    conn.Open();

                    using var trans = conn.BeginTransaction();
                    using var cmd = conn.CreateCommand();
                    cmd.Transaction = trans;
                    cmd.CommandText = @"
                        INSERT OR IGNORE INTO ThreatSignatures (Sha256, Name, Category, Severity, Source, AddedUtc)
                        VALUES ($sha256, $name, $category, $severity, $source, $addedUtc);
                    ";

                    var pSha = cmd.Parameters.Add("$sha256", SqliteType.Text);
                    var pName = cmd.Parameters.Add("$name", SqliteType.Text);
                    var pCat = cmd.Parameters.Add("$category", SqliteType.Text);
                    var pSev = cmd.Parameters.Add("$severity", SqliteType.Integer);
                    var pSource = cmd.Parameters.Add("$source", SqliteType.Text);
                    var pAdded = cmd.Parameters.Add("$addedUtc", SqliteType.Text);

                    string nowIso = DateTime.UtcNow.ToString("o");

                    foreach (var threat in pendingThreats)
                    {
                        pSha.Value = threat.Sha256;
                        pName.Value = threat.Name;
                        pCat.Value = threat.Category;
                        pSev.Value = threat.Severity;
                        pSource.Value = threat.Source;
                        pAdded.Value = nowIso;

                        int rowsInserted = cmd.ExecuteNonQuery();
                        if (rowsInserted > 0)
                        {
                            imported++;
                        }
                    }

                    trans.Commit();
                    foreach (var threat in pendingThreats)
                    {
                        EnforceCacheLimit();
                        _memoryCache.TryAdd(threat.Sha256, (threat.Name, threat.Category, threat.Severity));
                    }
                }

                if (imported > 0)
                {
                    UpdateDatabaseChecksum(_dbPath);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Tehdit imzaları SQLite veritabanına aktarılırken hata oluştu.");
                return 0;
            }

            return imported;
        }
    }
}

