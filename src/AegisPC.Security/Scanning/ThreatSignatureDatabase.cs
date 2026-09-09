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

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Genişletilebilir yerel tehdit imzası veritabanı (SQLite + InMemory Fast Cache).
    /// Gerçek dünya zararlı yazılım imzalarını abuse.ch MalwareBazaar API üzerinden indirip
    /// SQLite üzerinde saklar ve O(1) hızında bellek içi arama sunar.
    /// Yalnızca doğrulanmış EICAR test imzaları gömülü tutulur.
    /// </summary>
    public static class ThreatSignatureDatabase
    {
        private static readonly object _initLock = new();
        private static bool _isInitialized = false;
        private static string _dbPath = string.Empty;
        private static readonly ConcurrentDictionary<string, (string Name, string Category, int Severity)> _memoryCache = new(StringComparer.OrdinalIgnoreCase);

        public static int TotalSignaturesCount => _memoryCache.Count;
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
                    _memoryCache[sha] = (name, cat, sev);
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
                        // GÜVENLİK İHLALİ: İmza veritabanı dışarıdan kurcalanmış (tampering)
                        Log.ForContext("SourceContext", "SECURITY").Error(
                            "signature db tampering: threat signatures database hash mismatch. Expected {ExpectedHash}, Actual {ActualHash}. Recreating database.",
                            expectedHash, currentHash);

                        try
                        {
                            SqliteConnection.ClearAllPools();
                            File.Delete(dbPath);
                            File.Delete(hashPath);
                        }
                        catch (Exception delEx)
                        {
                            Log.Error(delEx, "Bütünlüğü bozulan tehdit veritabanı dosyası silinemedi: {DbPath}", dbPath);
                        }

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
            }
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

                // Eski/sentetik gömülü kayıtları temizle
                using var cleanCmd = conn.CreateCommand();
                cleanCmd.Transaction = trans;
                cleanCmd.CommandText = "DELETE FROM ThreatSignatures WHERE Source = 'Embedded';";
                cleanCmd.ExecuteNonQuery();

                // Yalnızca doğrulanmış gömülü tehditleri (EICAR) ekle
                using var insertCmd = conn.CreateCommand();
                insertCmd.Transaction = trans;
                insertCmd.CommandText = @"
                    INSERT OR REPLACE INTO ThreatSignatures (Sha256, Name, Category, Severity, Source, AddedUtc)
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
            if (string.IsNullOrEmpty(sha256))
                return (false, string.Empty, string.Empty, 0);

            // Boş dosya (0 byte) SHA256 değeri asla zararlı değildir
            if (sha256.Equals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", StringComparison.OrdinalIgnoreCase))
                return (false, string.Empty, string.Empty, 0);

            if (!_isInitialized)
            {
                Initialize();
            }

            if (_memoryCache.TryGetValue(sha256, out var match))
            {
                return (true, match.Name, match.Category, match.Severity);
            }

            return (false, string.Empty, string.Empty, 0);
        }

        /// <summary>
        /// Harici tehdit beslemelerinden (Abuse.ch MalwareBazaar vb.) toplu imza içe aktarma
        /// </summary>
        public static int ImportThreatHashes(IEnumerable<(string Sha256, string Name, string Category, int Severity, string Source)> newThreats)
        {
            if (!_isInitialized) Initialize();
            if (string.IsNullOrEmpty(_dbPath) || !File.Exists(_dbPath)) return 0;

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
                        INSERT OR REPLACE INTO ThreatSignatures (Sha256, Name, Category, Severity, Source, AddedUtc)
                        VALUES ($sha256, $name, $category, $severity, $source, $addedUtc);
                    ";

                    var pSha = cmd.Parameters.Add("$sha256", SqliteType.Text);
                    var pName = cmd.Parameters.Add("$name", SqliteType.Text);
                    var pCat = cmd.Parameters.Add("$category", SqliteType.Text);
                    var pSev = cmd.Parameters.Add("$severity", SqliteType.Integer);
                    var pSource = cmd.Parameters.Add("$source", SqliteType.Text);
                    var pAdded = cmd.Parameters.Add("$addedUtc", SqliteType.Text);

                    string nowIso = DateTime.UtcNow.ToString("o");

                    foreach (var threat in newThreats)
                    {
                        if (string.IsNullOrWhiteSpace(threat.Sha256) || threat.Sha256.Length < 32)
                            continue;

                        string normalizedHash = threat.Sha256.Trim().ToLowerInvariant();
                        string name = threat.Name ?? "Generic.Malware";
                        string category = threat.Category ?? "Malware";
                        int severity = threat.Severity > 0 ? threat.Severity : 100;
                        string source = threat.Source ?? "ThreatFeed";

                        pSha.Value = normalizedHash;
                        pName.Value = name;
                        pCat.Value = category;
                        pSev.Value = severity;
                        pSource.Value = source;
                        pAdded.Value = nowIso;

                        cmd.ExecuteNonQuery();

                        // Güncel RAM önbelleğine de anında ekle
                        EnforceCacheLimit();
                        _memoryCache[normalizedHash] = (name, category, severity);
                        imported++;
                    }

                    trans.Commit();
                }

                // Veritabanı dosyası güncellendiğinde SHA-256 sağlama toplamını güncelle
                UpdateDatabaseChecksum(_dbPath);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Tehdit imzaları SQLite veritabanına aktarılırken hata oluştu.");
            }

            return imported;
        }
    }
}
