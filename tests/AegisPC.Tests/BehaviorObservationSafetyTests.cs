using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AegisPC.Tests;

/// <summary>
/// Exercises the real behavior observer with inert telemetry and dependencies. These are security
/// unit tests; no OS process, native collector, network path, installed vault, or malware is touched.
/// </summary>
public sealed class BehaviorObservationSafetyTests
{
    /// <summary>Repeated legitimate encoded launches cannot amplify a feature or authorize any mutation.</summary>
    [Fact]
    public async Task RepeatedEncodedChildrenStayObservationOnlyWithoutQuarantineOrContainment()
    {
        var quarantine = new InertQuarantine();
        using var engine = new BehaviorEngine(quarantine);
        int containmentNotifications = 0;
        engine.OnThreatContained += (_, _) => containmentNotifications++;
        var creation = DateTime.UtcNow.AddMinutes(-2);
        for (int index = 0; index < 100; index++)
        {
            var observation = Observation(BehaviorEventType.ChildProcessSpawn, creation);
            observation.CommandLine = "powershell -EncodedCommand benign-synthetic-payload -ExecutionPolicy Bypass";
            observation.ExecutablePath = @"\\untrusted.invalid\share\synthetic-observation.exe";
            await engine.ProcessEventAsync(observation);
        }

        var incident = Assert.Single(await engine.GetActiveIncidentsAsync());
        AssertObservationOnly(incident);
        Assert.Equal(10, incident.RiskScore);
        Assert.Single(incident.Evidences);
        Assert.Equal(0, quarantine.Calls);
        Assert.Equal(0, containmentNotifications);
        Assert.Equal(64, Assert.Single(Sessions(engine)).Events.Count);
        Assert.False(Assert.Single(Sessions(engine)).IsContained);
        Assert.Empty(Assert.Single(Sessions(engine)).TrackedProcessTree);
    }

    /// <summary>Missing creation identity cannot merge unrelated behaviors merely because the PID matches.</summary>
    [Fact]
    public async Task UnknownActorWithRepeatedPidCannotFormACorrelatedAttackChain()
    {
        using var engine = new BehaviorEngine();
        foreach (var type in new[] { BehaviorEventType.ChildProcessSpawn, BehaviorEventType.RegistryPersistence,
                     BehaviorEventType.BrowserDataAccess, BehaviorEventType.ShadowCopyDeletion })
            await engine.ProcessEventAsync(Observation(type));

        var incidents = await engine.GetActiveIncidentsAsync();
        Assert.Equal(4, incidents.Count);
        Assert.All(incidents, incident =>
        {
            AssertObservationOnly(incident);
            Assert.Equal(0, incident.RootPid);
            Assert.Equal("UnknownProcess", incident.RootProcessName);
            Assert.Equal("Unknown", incident.ActorIdentityStatus);
            Assert.Null(incident.RootProcessStartTimeUtc);
            Assert.InRange(incident.RiskScore, 1, 30);
            Assert.Single(incident.Evidences);
        });
        Assert.Null(engine.LineageTracker.GetProcess(int.MaxValue - 123));
        Assert.Empty(engine.AttackChainCorrelator.GetActiveAttackChains(TimeSpan.FromMinutes(1)));
    }

    /// <summary>Invalid reported PIDs never become identified actors even if a creation time is supplied.</summary>
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(4)]
    public async Task InvalidPidRemainsUnknownAndCannotAuthorizeAnAction(int pid)
    {
        using var engine = new BehaviorEngine();
        var observation = Observation(BehaviorEventType.ProcessInjection, DateTime.UtcNow.AddMinutes(-1));
        observation.ProcessId = pid;
        await engine.ProcessEventAsync(observation);
        var incident = Assert.Single(await engine.GetActiveIncidentsAsync());
        AssertObservationOnly(incident);
        Assert.Equal(0, incident.RootPid);
        Assert.Equal("Unknown", incident.ActorIdentityStatus);
    }

    /// <summary>Event time and invalid or non-UTC start time cannot substitute for creation identity.</summary>
    [Fact]
    public async Task InvalidCreationTimeIsNotReplacedByEventTimestamp()
    {
        using var engine = new BehaviorEngine();
        var observation = Observation(BehaviorEventType.AmsiBypassAttempt);
        observation.ProcessStartTimeUtc = DateTime.SpecifyKind(observation.Timestamp, DateTimeKind.Unspecified);
        await engine.ProcessEventAsync(observation);
        observation = Observation(BehaviorEventType.RegistryPersistence);
        observation.ProcessStartTimeUtc = observation.Timestamp.AddDays(1);
        await engine.ProcessEventAsync(observation);
        Assert.All(await engine.GetActiveIncidentsAsync(), incident =>
        {
            Assert.Equal("Unknown", incident.ActorIdentityStatus);
            Assert.Null(incident.RootProcessStartTimeUtc);
            AssertObservationOnly(incident);
        });
    }

    /// <summary>Copies of one originating event count once even when wrappers use fresh event IDs and types.</summary>
    [Fact]
    public async Task OriginatingEventReplayCannotCreateIndependentFeatures()
    {
        using var engine = new BehaviorEngine();
        var first = Observation(BehaviorEventType.ChildProcessSpawn, DateTime.UtcNow.AddMinutes(-1));
        first.OriginatingEventId = "one-inert-source-event";
        await engine.ProcessEventAsync(first);
        var replay = Observation(BehaviorEventType.ShadowCopyDeletion, first.ProcessStartTimeUtc);
        replay.OriginatingEventId = first.OriginatingEventId;
        await engine.ProcessEventAsync(replay);
        await engine.ProcessEventAsync(first);
        var incident = Assert.Single(await engine.GetActiveIncidentsAsync());
        Assert.Equal(10, incident.RiskScore);
        Assert.Single(incident.Evidences);
        Assert.Equal(first.OriginatingEventId, incident.Evidences[0].OriginatingEventId);
        Assert.Single(Assert.Single(Sessions(engine)).Events);
    }

    /// <summary>PID reuse with different reported creation times does not join observation histories.</summary>
    [Fact]
    public async Task DifferentCreationIdentityPreventsPidReuseCorrelation()
    {
        using var engine = new BehaviorEngine();
        await engine.ProcessEventAsync(Observation(BehaviorEventType.ChildProcessSpawn, DateTime.UtcNow.AddMinutes(-3)));
        await engine.ProcessEventAsync(Observation(BehaviorEventType.AmsiBypassAttempt, DateTime.UtcNow.AddMinutes(-1)));
        var incidents = await engine.GetActiveIncidentsAsync();
        Assert.Equal(2, incidents.Count);
        Assert.All(incidents, incident => Assert.Single(incident.Evidences));
        Assert.NotEqual(incidents[0].RootProcessStartTimeUtc, incidents[1].RootProcessStartTimeUtc);
    }

    /// <summary>A reported parent PID cannot merge a child into an existing actor's session.</summary>
    [Fact]
    public async Task ParentPidWithoutParentCreationIdentityDoesNotBuildAProcessTree()
    {
        using var engine = new BehaviorEngine();
        var parent = Observation(BehaviorEventType.RegistryPersistence, DateTime.UtcNow.AddMinutes(-1));
        await engine.ProcessEventAsync(parent);
        var child = Observation(BehaviorEventType.ChildProcessSpawn, parent.ProcessStartTimeUtc);
        child.ProcessId = parent.ProcessId - 1;
        child.ParentProcessId = parent.ProcessId;
        await engine.ProcessEventAsync(child);
        Assert.Equal(2, (await engine.GetActiveIncidentsAsync()).Count);
        Assert.All(Sessions(engine), session => Assert.Empty(session.TrackedProcessTree));
    }

    /// <summary>Subscriber failures and mutated snapshots cannot prevent truthful audits or corrupt stored reports.</summary>
    [Fact]
    public async Task FailingOrMutatingSubscriberIsIsolatedFromLaterObserversAndAudit()
    {
        var audit = new InertAudit();
        var logger = new InertLogger();
        using var engine = new BehaviorEngine(logger: logger, auditLogService: audit);
        SecurityIncident? later = null;
        engine.OnIncidentCreated += incident =>
        {
            incident.Status = "Contained";
            incident.ActionTaken = "ProcessTerminated";
            incident.Evidences.Clear();
            throw new InvalidOperationException("Inert subscriber failure.");
        };
        engine.OnIncidentCreated += incident => later = incident;
        await engine.ProcessEventAsync(Observation(BehaviorEventType.ShadowCopyDeletion));

        Assert.NotNull(later);
        AssertObservationOnly(later!);
        Assert.NotEmpty(later!.Evidences);
        var persisted = Assert.Single(await engine.GetActiveIncidentsAsync());
        AssertObservationOnly(persisted);
        var recorded = Assert.Single(audit.Entries);
        Assert.Equal(AuditAction.ThreatObserved, recorded.Action);
        Assert.Contains("ProcessTerminated=false", recorded.Details);
        Assert.Contains("FileQuarantined=false", recorded.Details);
        Assert.Contains("subscriber failed", Assert.Single(logger.Warnings));
        persisted.ActionTaken = "FileQuarantined";
        persisted.Evidences.Clear();
        Assert.NotEmpty((await engine.GetIncidentByIdAsync(persisted.IncidentId))!.Evidences);
        Assert.Equal("None", (await engine.GetIncidentByIdAsync(persisted.IncidentId))!.ActionTaken);
    }

    /// <summary>Audit write failure is logged and cannot invent containment or stop other observers.</summary>
    [Fact]
    public async Task AuditFailureLeavesObservationAndNoActionReceiptIntact()
    {
        var audit = new InertAudit { FailWrites = true };
        var logger = new InertLogger();
        using var engine = new BehaviorEngine(logger: logger, auditLogService: audit);
        int observations = 0;
        engine.OnIncidentCreated += _ => observations++;
        await engine.ProcessEventAsync(Observation(BehaviorEventType.FileEncryptionAttempt));
        Assert.Equal(1, observations);
        AssertObservationOnly(Assert.Single(await engine.GetActiveIncidentsAsync()));
        Assert.Empty(audit.Entries);
        Assert.Contains("audit persistence failed", Assert.Single(logger.Warnings));
    }

    /// <summary>Floods of distinct Unknown actors retain fixed numbers of incidents, sessions, and replay IDs.</summary>
    [Fact]
    public async Task ObservationStateAndMetadataRemainBoundedUnderInertFlood()
    {
        using var engine = new BehaviorEngine();
        for (int index = 0; index < 4200; index++)
        {
            var observation = Observation(BehaviorEventType.ChildProcessSpawn);
            observation.Details = new string('x', 3000);
            await engine.ProcessEventAsync(observation);
        }
        Assert.Equal(256, Sessions(engine).Count);
        Assert.Equal(256, (await engine.GetActiveIncidentsAsync()).Count);
        Assert.Equal(4096, Dictionary(engine, "_originatingEvents").Count);
        Assert.All(Sessions(engine), session =>
        {
            Assert.Single(session.Events);
            Assert.Equal(2048, session.Events[0].Details.Length);
        });
    }

    /// <summary>Many reported categories remain heuristic and cannot become a Critical malware verdict.</summary>
    [Fact]
    public async Task DistinctCategoriesAreCappedAndNeverContainOrClaimMalwareProbability()
    {
        using var engine = new BehaviorEngine();
        var creation = DateTime.UtcNow.AddMinutes(-1);
        foreach (BehaviorEventType type in Enum.GetValues<BehaviorEventType>())
            await engine.ProcessEventAsync(Observation(type, creation));
        var incident = Assert.Single(await engine.GetActiveIncidentsAsync());
        AssertObservationOnly(incident);
        Assert.Equal(65, incident.RiskScore);
        Assert.Equal("SUSPICIOUS", incident.RiskLevel);
        Assert.All(incident.Evidences, evidence => Assert.InRange(evidence.Confidence, 0, 0.5));
        Assert.DoesNotContain("Trojan:", incident.ThreatName);
        Assert.DoesNotContain("zero-day", incident.ThreatName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Review acknowledgement changes review state without falsely claiming a security intervention.</summary>
    [Fact]
    public async Task LegacyRemediationMethodOnlyAcknowledgesObservationReview()
    {
        using var engine = new BehaviorEngine();
        await engine.ProcessEventAsync(Observation(BehaviorEventType.ProcessInjection));
        var incident = Assert.Single(await engine.GetActiveIncidentsAsync());
        Assert.True(await engine.RemediateIncidentAsync(incident.IncidentId));
        var reviewed = await engine.GetIncidentByIdAsync(incident.IncidentId);
        Assert.NotNull(reviewed);
        Assert.Equal("Reviewed", reviewed!.Status);
        Assert.Equal("None", reviewed.ActionTaken);
        Assert.Empty(await engine.GetActiveIncidentsAsync());
        Assert.False(await engine.RemediateIncidentAsync("inert-nonexistent-id"));
    }

    private static BehaviorEvent Observation(BehaviorEventType type, DateTime? creation = null) => new()
    {
        Source = "InertFixture",
        EventType = type,
        Timestamp = DateTime.UtcNow,
        ProcessId = int.MaxValue - 123,
        ProcessName = "synthetic-legitimate-fixture",
        ExecutablePath = "synthetic-observation-only.file",
        TargetResource = "synthetic-target",
        Details = "Reported event only; no actual operation was performed.",
        ProcessStartTimeUtc = creation,
        RiskWeight = double.MaxValue
    };

    private static void AssertObservationOnly(SecurityIncident incident)
    {
        Assert.Equal("ObservationOnly", incident.Status);
        Assert.Equal("None", incident.ActionTaken);
        Assert.Null(incident.RootHashSha256);
        Assert.InRange(incident.RiskScore, 1, 65);
        Assert.Contains("PerformedAction=None", incident.HumanExplanation);
        Assert.Contains("ContainmentPerformed=false", incident.HumanExplanation);
        Assert.Contains(incident.Timeline, entry => entry.Contains("FileQuarantined=false", StringComparison.Ordinal));
    }

    private static IDictionary Dictionary(BehaviorEngine engine, string name) =>
        (IDictionary)typeof(BehaviorEngine).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(engine)!;

    private static List<ProcessBehaviorSession> Sessions(BehaviorEngine engine)
    {
        var sessions = new List<ProcessBehaviorSession>();
        foreach (var value in Dictionary(engine, "_sessions").Values)
            sessions.Add((ProcessBehaviorSession)value!);
        return sessions;
    }

    private sealed record AuditEntry(AuditAction Action, string Details);

    private sealed class InertAudit : IAuditLogService
    {
        public bool FailWrites { get; init; }
        public List<AuditEntry> Entries { get; } = new();
        public Task LogActionAsync(AuditAction action, string targetType, string targetName,
            string? targetPath = null, string? details = null, AuditResult result = AuditResult.Success,
            string? errorMessage = null, CancellationToken cancellationToken = default)
        {
            if (FailWrites) throw new InvalidOperationException("Inert audit failure.");
            Entries.Add(new AuditEntry(action, details ?? string.Empty));
            return Task.CompletedTask;
        }
        public Task<List<AuditLogEntry>> GetLogsAsync(DateTime? from = null, DateTime? to = null,
            CancellationToken cancellationToken = default) => Task.FromResult(new List<AuditLogEntry>());
    }

    private sealed class InertLogger : ILogger<BehaviorEngine>
    {
        public List<string> Warnings { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning) Warnings.Add(formatter(state, exception));
        }
    }

    private sealed class InertQuarantine : IQuarantineService
    {
        public int Calls { get; private set; }
        public string? LastError => null;
        public event Action<QuarantineEntry>? OnFileQuarantined { add { } remove { } }
        public event Action<int>? OnFileRestored { add { } remove { } }
        public event Action<int>? OnFileDeleted { add { } remove { } }
        public Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken = default)
        { Calls++; return Task.FromResult(false); }
        public Task<bool> RestoreFileAsync(int id, CancellationToken cancellationToken = default)
        { Calls++; return Task.FromResult(false); }
        public Task<bool> RestoreFileAsync(int id, string? customDestinationPath, CancellationToken cancellationToken = default)
        { Calls++; return Task.FromResult(false); }
        public Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default)
        { Calls++; return Task.FromResult(new List<QuarantineEntry>()); }
        public Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default)
        { Calls++; return Task.FromResult(false); }
        public Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default)
        { Calls++; return Task.FromResult<QuarantineEntry?>(null); }
    }
}
