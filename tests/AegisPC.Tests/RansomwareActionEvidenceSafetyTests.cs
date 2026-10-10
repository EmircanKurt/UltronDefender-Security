using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests;

/// <summary>
/// Exercises the real observation handler with inert dependencies, synthetic PID/path strings,
/// and no process, filesystem, registry, native canary, Defender, or installed-vault interaction.
/// </summary>
public sealed class RansomwareActionEvidenceSafetyTests
{
    [Theory]
    [InlineData(70)]
    [InlineData(90)]
    [InlineData(100)]
    [InlineData(int.MaxValue)]
    public async Task HighHeuristicScoreAndReportedPidCannotAuthorizeContainment(int score)
    {
        var quarantine = new InertQuarantine();
        var audit = new InertAudit();
        var handler = new RansomwareEnforcementHandler(quarantine, auditLogService: audit);
        RansomwareAlertEventArgs? observed = null;
        handler.OnRansomwareAttemptDetected += (_, alert) => observed = alert;

        var assessment = await handler.EvaluateAndContainThreatAsync(
            "synthetic-observation-only.file", "Synthetic heuristic; not malware evidence", score,
            pid: int.MaxValue - 123);

        AssertZeroDamage(assessment);
        AssertObservationOnly(observed);
        Assert.Equal(0, handler.TotalBlockedAttempts);
        Assert.Equal(0, quarantine.Calls);
        var recorded = Assert.Single(audit.Entries);
        Assert.Equal(AuditAction.ThreatObserved, recorded.Action);
        Assert.Equal(AuditResult.Success, recorded.Result);
    }

    [Fact]
    public async Task UncorrelatedPathDoesNotTriggerFileLockDiscoveryOrNetworkFileAccess()
    {
        var quarantine = new InertQuarantine();
        var handler = new RansomwareEnforcementHandler(quarantine);
        RansomwareAlertEventArgs? observed = null;
        handler.OnRansomwareAttemptDetected += (_, alert) => observed = alert;

        // A string payload only: this fixture must never open or probe a network location.
        const string syntheticUnc = @"\\untrusted.invalid\share\observation-only.bin";
        var assessment = await handler.EvaluateAndContainThreatAsync(
            syntheticUnc, "Synthetic observation", 100, pid: 0);

        AssertZeroDamage(assessment);
        AssertObservationOnly(observed);
        Assert.Equal(syntheticUnc, observed!.OffendingFilePath);
        Assert.Equal(0, quarantine.Calls);
    }

    [Fact]
    public async Task RepeatedAlertsDoNotIncrementVerifiedBlockedAttemptsOrInventDamage()
    {
        var quarantine = new InertQuarantine();
        var audit = new InertAudit();
        var handler = new RansomwareEnforcementHandler(quarantine, auditLogService: audit);
        var alerts = new List<RansomwareAlertEventArgs>();
        int notifications = 0;
        handler.OnRansomwareAttemptDetected += (_, alert) => alerts.Add(alert);
        handler.OnNotificationRaised += (_, _, _) => notifications++;

        for (int index = 0; index < 3; index++)
            AssertZeroDamage(await handler.EvaluateAndContainThreatAsync(
                "synthetic-observation-only.file", "Synthetic unverified activity", 100));

        Assert.Equal(3, alerts.Count);
        Assert.Equal(3, notifications);
        Assert.Equal(3, audit.Entries.Count);
        Assert.All(alerts, alert => AssertObservationOnly(alert));
        Assert.Equal(0, handler.TotalBlockedAttempts);
        Assert.Equal(0, quarantine.Calls);
    }

    [Fact]
    public async Task NotificationsAndAuditDescribeObservationRatherThanSuccessfulContainment()
    {
        var audit = new InertAudit();
        var handler = new RansomwareEnforcementHandler(auditLogService: audit);
        string? title = null, message = null, severity = null;
        handler.OnNotificationRaised += (t, m, s) => { title = t; message = m; severity = s; };

        AssertZeroDamage(await handler.EvaluateAndContainThreatAsync(
            "synthetic-observation-only.file", "A heuristic score is not authoritative proof", 95));

        Assert.Equal("Warning", severity);
        Assert.Equal("Suspicious file activity observed", title);
        Assert.Contains("unverified", message!);
        Assert.Contains("No process was terminated", message!);
        Assert.Contains("no file was quarantined or blocked", message!);
        var recorded = Assert.Single(audit.Entries);
        Assert.Equal(AuditAction.ThreatObserved, recorded.Action);
        Assert.Equal("RansomwareObservation", recorded.TargetType);
        Assert.Equal("UnknownProcess", recorded.TargetName);
        Assert.Contains("ProcessCorrelationVerified=false", recorded.Details!);
        Assert.Contains("ProcessTerminated=false", recorded.Details!);
        Assert.Contains("FileQuarantined=false", recorded.Details!);
        Assert.Contains("FilesAffected=0; FilesBlocked=0; ContainmentPerformed=false", recorded.Details!);
    }

    [Fact]
    public async Task ObserverExceptionsDoNotSkipOtherObserversAuditOrZeroDamageResult()
    {
        var audit = new InertAudit();
        var handler = new RansomwareEnforcementHandler(auditLogService: audit);
        int alerts = 0, notifications = 0;
        handler.OnRansomwareAttemptDetected += (_, _) => throw new InvalidOperationException("Inert observer failure.");
        handler.OnRansomwareAttemptDetected += (_, alert) => { AssertObservationOnly(alert); alerts++; };
        handler.OnNotificationRaised += (_, _, _) => throw new InvalidOperationException("Inert notification failure.");
        handler.OnNotificationRaised += (_, _, _) => notifications++;

        AssertZeroDamage(await handler.EvaluateAndContainThreatAsync(
            "synthetic-observation-only.file", "Synthetic observation", 100));

        Assert.Equal(1, alerts);
        Assert.Equal(1, notifications);
        Assert.Single(audit.Entries);
        Assert.Equal(0, handler.TotalBlockedAttempts);
    }

    [Fact]
    public async Task MutableObserverPayloadCannotForgeLaterObservationOrAuditContainment()
    {
        var audit = new InertAudit();
        var handler = new RansomwareEnforcementHandler(auditLogService: audit);
        RansomwareAlertEventArgs? laterObservation = null;
        handler.OnRansomwareAttemptDetected += (_, alert) =>
        {
            alert.ProcessTerminated = true;
            alert.OffendingProcessId = 123;
            alert.OffendingProcessName = "ForgedProcess";
            alert.FilesAffected = 999;
            alert.DetectionReason = "Forged containment claim";
        };
        handler.OnRansomwareAttemptDetected += (_, alert) => laterObservation = alert;

        AssertZeroDamage(await handler.EvaluateAndContainThreatAsync(
            "synthetic-observation-only.file", "Original observation", 100));

        AssertObservationOnly(laterObservation);
        var recorded = Assert.Single(audit.Entries);
        Assert.Equal("UnknownProcess", recorded.TargetName);
        Assert.DoesNotContain("Forged", recorded.Details!);
        Assert.Contains("Original observation", recorded.Details!);
    }

    [Fact]
    public async Task AuditPersistenceFailureDoesNotPretendAnActionOccurredOrPreventObservation()
    {
        var audit = new InertAudit { FailWrites = true };
        var quarantine = new InertQuarantine();
        var handler = new RansomwareEnforcementHandler(quarantine, auditLogService: audit);
        int alerts = 0, notifications = 0;
        handler.OnRansomwareAttemptDetected += (_, alert) => { AssertObservationOnly(alert); alerts++; };
        handler.OnNotificationRaised += (_, _, _) => notifications++;

        AssertZeroDamage(await handler.EvaluateAndContainThreatAsync(
            "synthetic-observation-only.file", "Synthetic observation", 100));

        Assert.Equal(1, alerts);
        Assert.Equal(1, notifications);
        Assert.Empty(audit.Entries);
        Assert.Equal(0, handler.TotalBlockedAttempts);
        Assert.Equal(0, quarantine.Calls);
    }

    [Fact]
    public async Task UncorrelatedAllowlistCallbackIsNotInvokedToResolveOrTrustAProcess()
    {
        var handler = new RansomwareEnforcementHandler();
        AssertZeroDamage(await handler.EvaluateAndContainThreatAsync(
            "synthetic-observation-only.file", "Synthetic observation", 100,
            pid: int.MaxValue - 123,
            isAppAllowed: _ => throw new InvalidOperationException("An uncorrelated allowance must not be consulted.")));
        Assert.Equal(0, handler.TotalBlockedAttempts);
    }

    private static void AssertZeroDamage(RansomwareDamageAssessment? assessment)
    {
        Assert.NotNull(assessment);
        Assert.Equal(0, assessment!.FilesTargeted);
        Assert.Equal(0, assessment.FilesModified);
        Assert.Equal(0, assessment.FilesRenamed);
        Assert.Equal(0, assessment.FilesDeleted);
        Assert.Equal(0, assessment.FilesBlocked);
        Assert.Equal("UnknownProcess", assessment.OffendingProcess);
    }

    private static void AssertObservationOnly(RansomwareAlertEventArgs? observed)
    {
        Assert.NotNull(observed);
        Assert.Equal(0, observed!.OffendingProcessId);
        Assert.Equal("UnknownProcess", observed.OffendingProcessName);
        Assert.False(observed.ProcessTerminated);
        Assert.Equal(0, observed.FilesAffected);
        Assert.StartsWith("Unverified observation: ", observed.DetectionReason);
    }

    private sealed record AuditEntry(AuditAction Action, string TargetType, string TargetName,
        string? TargetPath, string? Details, AuditResult Result);

    private sealed class InertAudit : IAuditLogService
    {
        public bool FailWrites { get; init; }
        public List<AuditEntry> Entries { get; } = new();
        public Task LogActionAsync(AuditAction action, string targetType, string targetName,
            string? targetPath = null, string? details = null, AuditResult result = AuditResult.Success,
            string? errorMessage = null, CancellationToken cancellationToken = default)
        {
            if (FailWrites) throw new InvalidOperationException("Inert audit persistence failure.");
            Entries.Add(new AuditEntry(action, targetType, targetName, targetPath, details, result));
            return Task.CompletedTask;
        }
        public Task<List<AuditLogEntry>> GetLogsAsync(DateTime? from = null, DateTime? to = null,
            CancellationToken cancellationToken = default) => Task.FromResult(new List<AuditLogEntry>());
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
