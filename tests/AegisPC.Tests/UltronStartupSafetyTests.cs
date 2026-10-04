using AegisPC.App.Services;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Database;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Microsoft.Data.Sqlite;
using Xunit;
using System.IO;

namespace AegisPC.Tests;

/// <summary>Inert startup, migration and UI acknowledgement regressions limited to explicitly created temporary files.</summary>
public sealed class UltronStartupSafetyTests
{
    /// <summary>Legacy databases missing AuditLogs are ready before consumers write an audit; initialization is idempotent.</summary>
    [Fact]
    public async Task MissingAuditTable_IsCreatedBeforeUse()
    {
        string folder = Path.Combine(Path.GetTempPath(), "UltronSchemaFixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var database = new DatabaseService(Path.Combine(folder, "test.db"));
            await database.InitializeAsync();
            using (var connection = database.GetConnection())
            {
                using var legacy = connection.CreateCommand();
                legacy.CommandText = "DROP TABLE AuditLogs"; // Only this fixture's private database.
                await legacy.ExecuteNonQueryAsync();
            }
            await database.InitializeAsync();
            await database.InitializeAsync();
            using var ready = database.GetConnection();
            using var query = ready.CreateCommand();
            query.CommandText = "SELECT COUNT(*) FROM AuditLogs";
            Assert.Equal(0L, await query.ExecuteScalarAsync());
        }
        finally { SqliteConnection.ClearAllPools(); Directory.Delete(folder, true); }
    }
    /// <summary>Schema failure rolls back the partially created tables instead of presenting schema completion.</summary>
    [Fact]
    public async Task InvalidLegacySchema_RollsBackNewTables()
    {
        string folder = Path.Combine(Path.GetTempPath(), "UltronSchemaFixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var database = new DatabaseService(Path.Combine(folder, "test.db"));
            using (var connection = database.GetConnection())
            {
                using var seed = connection.CreateCommand();
                seed.CommandText = "CREATE TABLE AuditLogs (Id INTEGER PRIMARY KEY)";
                await seed.ExecuteNonQueryAsync();
            }
            await Assert.ThrowsAsync<SqliteException>(() => database.InitializeAsync());
            using var ready = database.GetConnection();
            using var query = ready.CreateCommand();
            query.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE name='SecurityFindings'";
            Assert.Equal(0L, await query.ExecuteScalarAsync());
        }
        finally { SqliteConnection.ClearAllPools(); Directory.Delete(folder, true); }
    }
    /// <summary>Reviewing a known-malware finding is not a quarantine deletion, allowlist operation or malware resolution.</summary>
    [Fact]
    public async Task ReviewAcknowledgement_DoesNotResolveFindingOrAddExemption()
    {
        var findings = new SecurityFindingService();
        var finding = new SecurityFinding { ObjectPath = "synthetic-path", RiskLevel = RiskLevel.ConfirmedMalicious,
            SHA256 = new string('A', 64), Status = FindingStatus.Active };
        await findings.AddFindingAsync(finding);
        var allowlist = new RejectingAllowlist();
        using var model = new IncidentCenterViewModel(findingService: findings, allowlistService: allowlist);
        var incident = new SecurityIncident { IncidentId = "FIND-" + finding.Id.ToString("N")[..8], RootExecutablePath = finding.ObjectPath };
        await model.RemediateIncidentAsync(incident);
        Assert.Equal("Reviewed", incident.Status);
        Assert.Equal("None", incident.ActionTaken);
        Assert.Equal(FindingStatus.Active, finding.Status);
        Assert.False(finding.IsAllowlisted);
        Assert.Equal(0, allowlist.Writes);
    }
    /// <summary>Reports expose typed failures without raw exception or private target paths.</summary>
    [Fact]
    public void FailedReport_IncludesSafeReasonAndCorrelation()
    {
        var failure = new ScanFailureInfo { Stage = ScanFailureStage.Scanning, Reason = ScanFailureReason.ChannelClosed,
            SafeMessage = "The inspection channel closed unexpectedly.", CorrelationId = Guid.NewGuid() };
        string report = ScanReportGenerator.GenerateTextReport(DateTime.UtcNow, "1s", "Custom", 4, Array.Empty<SecurityFinding>(),
            scanStatus: ScanStatus.Failed, failureInfo: failure);
        Assert.Contains("ChannelClosed", report);
        Assert.Contains(failure.CorrelationId.ToString(), report);
        Assert.Contains(failure.SafeMessage, report);
    }
    /// <summary>Activation resolves documents on every enable, including disabled-at-boot then enabled later.</summary>
    [Fact]
    public async Task ShieldEnable_UsesSharedResolverBeforeStart()
    {
        string folder = Path.Combine(Path.GetTempPath(), "UltronShieldFixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var resolver = new FixtureTargets(folder);
            var engine = new FixtureShield();
            var activation = new RansomwareShieldActivation(engine, resolver);
            await activation.StartAsync(); await activation.StopAsync(); await activation.StartAsync();
            Assert.Equal(2, resolver.Calls);
            Assert.Equal(2, engine.Starts);
            Assert.True(engine.IsShieldActive);
        }
        finally { Directory.Delete(folder); }
    }
    /// <summary>A low-confidence observation at the same path cannot hide independent authoritative content evidence.</summary>
    [Fact]
    public async Task SamePathObservation_DoesNotHideConfirmedFinding()
    {
        var findings = new SecurityFindingService();
        await findings.AddFindingAsync(new SecurityFinding { ObjectPath = "synthetic-path", RiskLevel = RiskLevel.ConfirmedMalicious,
            SHA256 = new string('A', 64), Status = FindingStatus.Active });
        using var behavior = new BehaviorEngine();
        await behavior.ProcessEventAsync(new BehaviorEvent { ProcessId = int.MaxValue - 22,
            ProcessStartTimeUtc = DateTime.UtcNow.AddMinutes(-1), ProcessName = "synthetic", ExecutablePath = "synthetic-path",
            EventType = BehaviorEventType.ChildProcessSpawn });
        using var model = new IncidentCenterViewModel(behavior, findings);
        await model.LoadIncidentsAsync();
        Assert.Contains(model.Incidents, i => i.IncidentId.StartsWith("INC-", StringComparison.Ordinal));
        Assert.Contains(model.Incidents, i => i.IncidentId.StartsWith("FIND-", StringComparison.Ordinal) && i.RootHashSha256 == new string('A', 64));
        Assert.Equal(2, model.Incidents.Count);
    }

    private sealed class FixtureTargets(string path) : IScanTargetResolver
    {
        internal int Calls;
        public Task<ScanTargetResolution> ResolveAsync(CancellationToken token = default)
        { Calls++; return Task.FromResult(new ScanTargetResolution(Array.Empty<ScanProfileTarget>(), new[] { new ScanDirectoryTarget { Path = path, Kind = ScanDirectoryKind.Documents } }, true)); }
    }
    private sealed class FixtureShield : IRansomwareProtectionEngine
    {
        internal int Starts;
        private readonly List<string> _roots = new();
        public bool IsShieldActive { get; private set; }
        public void StartShield() { Assert.NotEmpty(_roots); Starts++; IsShieldActive = true; }
        public void StopShield() => IsShieldActive = false;
        public IReadOnlyList<string> ProtectedDirectories => _roots;
        public IReadOnlyList<AllowedRansomwareApplication> AllowedApplications => Array.Empty<AllowedRansomwareApplication>();
        public int CanaryFileCount => 0;
        public int TotalBlockedAttempts => 0;
        public void AddProtectedDirectory(string path) => _roots.Add(path);
        public void RemoveProtectedDirectory(string path) { }
        public void AddAllowedApplication(string path, string? name = null) { }
        public void RemoveAllowedApplication(string path) { }
        public bool IsApplicationAllowed(string path) => false;
        public void CleanupCanaryFiles() { }
        public Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(string path, string reason, int riskScore, int pid = 0, DateTime? timestamp = null) => Task.FromResult<RansomwareDamageAssessment?>(null);
        public event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected { add { } remove { } }
        public event Action<string, string, string>? OnNotificationRaised { add { } remove { } }
    }
    private sealed class RejectingAllowlist : IAllowlistService
    {
        internal int Writes;
        public bool IsAllowlisted(string hash) => false;
        public bool IsPathAllowlisted(string path) => false;
        public Task<bool> IsAllowlistedAsync(string hash, CancellationToken token = default) => Task.FromResult(false);
        public Task<bool> IsPathAllowlistedAsync(string path, CancellationToken token = default) => Task.FromResult(false);
        public Task AddToAllowlistAsync(AllowlistEntry entry, CancellationToken token = default) { Writes++; throw new InvalidOperationException("Review must not create exemptions."); }
        public Task RemoveFromAllowlistAsync(int id, CancellationToken token = default) => Task.CompletedTask;
        public Task<List<AllowlistEntry>> GetAllowlistAsync(CancellationToken token = default) => Task.FromResult(new List<AllowlistEntry>());
        public Task<bool> CheckHashChangedAsync(AllowlistEntry entry, CancellationToken token = default) => Task.FromResult(false);
    }
}
