using System;
using System.Data.Common;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using Microsoft.Data.Sqlite;

namespace AegisPC.Infrastructure.Database
{
    /// <summary>
    /// Service for managing the SQLite database connection and initialization.
    /// </summary>
    public class DatabaseService : IDatabaseService
    {
        private readonly string _connectionString;
        private readonly string _dbPath;

        /// <summary>
        /// Initializes a new instance of the <see cref="DatabaseService"/> class.
        /// </summary>
        public DatabaseService()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var aegisDir = Path.Combine(appData, "AegisPC");
            Directory.CreateDirectory(aegisDir);

            _dbPath = Path.Combine(aegisDir, "aegis.db");
            _connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = _dbPath,
                Pooling = true,
                ForeignKeys = true
            }.ToString();
        }

        public string GetConnectionString() => _connectionString;

        /// <summary>
        /// Gets a new SQLite database connection.
        /// </summary>
        public SqliteConnection GetConnection()
        {
            var connection = new SqliteConnection(_connectionString);
            connection.Open();
            return connection;
        }

        public DbConnection CreateConnection() => GetConnection();

        /// <summary>
        /// Initializes the database schema.
        /// </summary>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            using var connection = GetConnection();
            using var command = connection.CreateCommand();

            command.CommandText = @"
                CREATE TABLE IF NOT EXISTS SecurityFindings (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ObjectPath TEXT NOT NULL,
                    ObjectName TEXT NOT NULL,
                    SHA256 TEXT,
                    SHA1 TEXT,
                    RiskLevel INTEGER NOT NULL,
                    RiskScore INTEGER,
                    Category INTEGER NOT NULL,
                    Title TEXT NOT NULL,
                    Description TEXT,
                    RiskReasons TEXT,
                    ConfidenceLevel INTEGER NOT NULL,
                    IsAllowlisted INTEGER DEFAULT 0,
                    FirstObserved TEXT NOT NULL,
                    LastObserved TEXT NOT NULL,
                    Status INTEGER DEFAULT 0,
                    CreatedAt TEXT NOT NULL,
                    UpdatedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ScanHistory (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ScanType INTEGER NOT NULL,
                    StartedAt TEXT NOT NULL,
                    CompletedAt TEXT,
                    Status INTEGER NOT NULL,
                    TotalFiles INTEGER DEFAULT 0,
                    ScannedFiles INTEGER DEFAULT 0,
                    SkippedFiles INTEGER DEFAULT 0,
                    FindingsCount INTEGER DEFAULT 0,
                    CustomPath TEXT,
                    ElapsedMs INTEGER
                );

                CREATE TABLE IF NOT EXISTS FileHashes (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    FilePath TEXT NOT NULL,
                    SHA256 TEXT NOT NULL,
                    SHA1 TEXT,
                    FileSize INTEGER NOT NULL,
                    LastModified TEXT NOT NULL,
                    ComputedAt TEXT NOT NULL,
                    UNIQUE(FilePath, LastModified)
                );

                CREATE TABLE IF NOT EXISTS ProcessSamples (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ProcessName TEXT NOT NULL,
                    PID INTEGER NOT NULL,
                    CpuPercent REAL,
                    MemoryBytes INTEGER,
                    DiskReadBps INTEGER,
                    DiskWriteBps INTEGER,
                    NetworkBps INTEGER,
                    SampledAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS PerformanceSamples (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    CpuPercent REAL NOT NULL,
                    MemoryUsedBytes INTEGER NOT NULL,
                    MemoryTotalBytes INTEGER NOT NULL,
                    DiskReadBps INTEGER,
                    DiskWriteBps INTEGER,
                    DiskUsagePercent REAL,
                    NetworkDownBps INTEGER,
                    NetworkUpBps INTEGER,
                    ActiveProcesses INTEGER,
                    SampledAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS CrashEvents (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    EventType INTEGER NOT NULL,
                    ApplicationName TEXT,
                    ApplicationPath TEXT,
                    ExceptionCode TEXT,
                    EventId INTEGER,
                    ProviderName TEXT,
                    OccurredAt TEXT NOT NULL,
                    CpuAtTime REAL,
                    MemoryAtTime INTEGER,
                    CorrelationId TEXT,
                    RawEventData TEXT,
                    AnalysisResult TEXT,
                    ConfidenceLevel INTEGER,
                    CreatedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS WindowsEvents (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    LogName TEXT NOT NULL,
                    ProviderName TEXT NOT NULL,
                    EventId INTEGER NOT NULL,
                    Level INTEGER NOT NULL,
                    Message TEXT,
                    TimeCreated TEXT NOT NULL,
                    MachineName TEXT,
                    ProcessId INTEGER,
                    RawXml TEXT,
                    CreatedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS Recommendations (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Category INTEGER NOT NULL,
                    Title TEXT NOT NULL,
                    Description TEXT NOT NULL,
                    Reasoning TEXT NOT NULL,
                    RiskLevel INTEGER NOT NULL,
                    EstimatedImpact TEXT,
                    ActionType TEXT,
                    ActionData TEXT,
                    Status INTEGER DEFAULT 0,
                    DismissedForever INTEGER DEFAULT 0,
                    CreatedAt TEXT NOT NULL,
                    UpdatedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS QuarantineItems (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    OriginalPath TEXT NOT NULL,
                    QuarantinePath TEXT NOT NULL,
                    FileName TEXT NOT NULL,
                    SHA256 TEXT NOT NULL,
                    FileSize INTEGER NOT NULL,
                    Reason TEXT NOT NULL,
                    RiskLevel INTEGER NOT NULL,
                    QuarantinedAt TEXT NOT NULL,
                    RestoredAt TEXT,
                    Status INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS StartupItems (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Name TEXT NOT NULL,
                    Publisher TEXT,
                    FilePath TEXT,
                    Arguments TEXT,
                    Source TEXT NOT NULL,
                    RegistryPath TEXT,
                    IsEnabled INTEGER DEFAULT 1,
                    ImpactLevel INTEGER,
                    RiskLevel INTEGER DEFAULT 5,
                    BackupValue TEXT,
                    LastAnalyzedAt TEXT,
                    CreatedAt TEXT NOT NULL,
                    UpdatedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS AuditLogs (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Action INTEGER NOT NULL,
                    TargetType TEXT NOT NULL,
                    TargetName TEXT NOT NULL,
                    TargetPath TEXT,
                    Details TEXT,
                    Result INTEGER NOT NULL,
                    ErrorMessage TEXT,
                    Timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ApplicationInventory (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    DisplayName TEXT NOT NULL,
                    Publisher TEXT,
                    Version TEXT,
                    InstallDate TEXT,
                    EstimatedSizeKB INTEGER,
                    InstallLocation TEXT,
                    UninstallString TEXT,
                    RegistrySource TEXT,
                    LastKnownUsage TEXT,
                    UsageReliable INTEGER DEFAULT 0,
                    TrustLevel INTEGER DEFAULT 5,
                    LastScannedAt TEXT,
                    CreatedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS Allowlist (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    FilePath TEXT NOT NULL,
                    SHA256 TEXT NOT NULL,
                    FileName TEXT NOT NULL,
                    AddedBy TEXT DEFAULT 'user',
                    Reason TEXT,
                    AddedAt TEXT NOT NULL,
                    IsActive INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS SchemaVersion (
                    Version INTEGER PRIMARY KEY,
                    AppliedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS RealTimeEvents (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    EventType TEXT NOT NULL,
                    FilePath TEXT,
                    ProcessName TEXT,
                    ProcessId INTEGER,
                    SHA256 TEXT,
                    RiskLevel INTEGER,
                    ActionTaken TEXT NOT NULL,
                    Details TEXT,
                    DetectedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ProtectionLog (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Component TEXT NOT NULL,
                    Action TEXT NOT NULL,
                    Details TEXT,
                    Timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ThreatFeeds (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Indicator TEXT NOT NULL UNIQUE,
                    Type TEXT NOT NULL,
                    Category INTEGER NOT NULL,
                    Source TEXT,
                    AddedAt TEXT NOT NULL,
                    ExpiresAt TEXT
                );

                CREATE TABLE IF NOT EXISTS BlockedConnections (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Domain TEXT,
                    IpAddress TEXT,
                    Port INTEGER,
                    Category INTEGER NOT NULL,
                    ProcessName TEXT,
                    ProcessId INTEGER,
                    BlockedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ScanSchedules (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Name TEXT NOT NULL,
                    ScanType INTEGER NOT NULL,
                    CronExpression TEXT NOT NULL,
                    IsEnabled INTEGER DEFAULT 1,
                    RunOnlyWhenIdle INTEGER DEFAULT 1,
                    LastRunAt TEXT,
                    NextRunAt TEXT,
                    CreatedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS CloudReputationCache (
                    SHA256 TEXT PRIMARY KEY,
                    Verdict TEXT NOT NULL,
                    DetectionCount INTEGER,
                    Source TEXT NOT NULL,
                    FirstSeen TEXT,
                    CheckedAt TEXT NOT NULL,
                    ExpiresAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ParentalRules (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    RuleName TEXT NOT NULL,
                    RuleType TEXT NOT NULL,
                    Target TEXT,
                    DailyLimitMinutes INTEGER,
                    IsEnabled INTEGER DEFAULT 1,
                    PinHash TEXT,
                    CreatedAt TEXT NOT NULL,
                    UpdatedAt TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS AppUsageHistory (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    AppName TEXT NOT NULL,
                    AppPath TEXT,
                    Category TEXT,
                    UsageSeconds INTEGER NOT NULL,
                    Date TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS IX_RealTimeEvents_Time ON RealTimeEvents(DetectedAt);
                CREATE INDEX IF NOT EXISTS IX_BlockedConnections_Time ON BlockedConnections(BlockedAt);
                CREATE INDEX IF NOT EXISTS IX_ThreatFeeds_Indicator ON ThreatFeeds(Indicator);
                CREATE INDEX IF NOT EXISTS IX_AppUsage_Date ON AppUsageHistory(Date);

                CREATE INDEX IF NOT EXISTS IX_SecurityFindings_Risk ON SecurityFindings(RiskLevel);
                CREATE INDEX IF NOT EXISTS IX_ScanHistory_Started ON ScanHistory(StartedAt);
                CREATE INDEX IF NOT EXISTS IX_Perf_Samples_Date ON PerformanceSamples(SampledAt);
                CREATE INDEX IF NOT EXISTS IX_Proc_Samples_Date ON ProcessSamples(SampledAt);
                CREATE INDEX IF NOT EXISTS IX_AuditLogs_Time ON AuditLogs(Timestamp);
                CREATE INDEX IF NOT EXISTS IX_WindowsEvents_Time ON WindowsEvents(TimeCreated);
                CREATE INDEX IF NOT EXISTS IX_CrashEvents_Time ON CrashEvents(OccurredAt);
            ";
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}
