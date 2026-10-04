using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime;

public partial class BehaviorEngine
{
    private static SecurityIncident CreateObservationIncident(
        ProcessBehaviorSession session, ObservationEvaluation evaluation, DateTime now)
    {
        const string actionReceipt = "RequestedAction=None; PerformedAction=None; " +
            "ProcessTerminated=false; FileQuarantined=false; ContainmentPerformed=false";
        var timeline = session.Events.Select(e =>
            $"[{e.Timestamp:O}] {e.EventType}; source={e.Source}; event={e.EventId}; " +
            $"origin={e.OriginatingEventId}; reported PID={e.ProcessId}; target={e.TargetResource}; " +
            $"command={e.CommandLine}; details={e.Details}").ToList();
        timeline.Add($"[{now:O}] Observation-only receipt: {actionReceipt}");
        var explanation = new StringBuilder();
        explanation.AppendLine("Behavior telemetry observed; malicious intent and operation success are unverified.");
        explanation.AppendLine(session.HasCreationIdentity
            ? $"Actor: reported creation identity (PID {session.RootPid}, created {session.StartedAt:O}); not authenticated."
            : "Actor: Unknown. A reported PID or event timestamp does not establish process creation identity.");
        explanation.AppendLine($"Heuristic review score: {evaluation.Score}/100; no malware probability or MITRE conclusion.");
        foreach (var evidence in evaluation.Evidences) explanation.AppendLine(evidence.Explanation);
        explanation.AppendLine($"Actual action receipt: {actionReceipt}.");
        var incident = new SecurityIncident
        {
            Title = "Behavior observations require review",
            ThreatName = "Unverified behavior observations",
            CreatedAt = now,
            RootPid = session.RootPid,
            RootProcessName = session.RootProcessName,
            RootExecutablePath = session.RootExecutablePath,
            RootProcessStartTimeUtc = session.HasCreationIdentity ? session.StartedAt : null,
            ActorIdentityStatus = session.HasCreationIdentity ? "ReportedCreationIdentity" : "Unknown",
            RiskScore = evaluation.Score,
            RiskLevel = session.HasCreationIdentity ? "SUSPICIOUS" : "UNKNOWN",
            Status = "ObservationOnly",
            ActionTaken = "None",
            Evidences = evaluation.Evidences,
            Timeline = timeline,
            HumanExplanation = explanation.ToString(),
            RecommendedUserAction = "Review the reported evidence and run an independent scan if needed. " +
                "No process was terminated, no file was quarantined, and no activity was blocked."
        };
        if (session.IncidentId != null) incident.IncidentId = session.IncidentId;
        session.IncidentId = incident.IncidentId;
        return incident;
    }

    private void PublishObservation(SecurityIncident incident)
    {
        var subscribers = OnIncidentCreated;
        if (subscribers == null) return;
        foreach (Action<SecurityIncident> subscriber in subscribers.GetInvocationList())
        {
            try { subscriber(CopyIncident(incident)); }
            catch (Exception exception)
            {
                LogObservationFailure(exception, "A behavior observation subscriber failed; no action was performed.");
            }
        }
    }

    private async Task RecordObservationAsync(SecurityIncident incident, CancellationToken cancellationToken)
    {
        if (_auditLogService == null) return;
        try
        {
            await _auditLogService.LogActionAsync(AuditAction.ThreatObserved, "BehaviorObservation",
                incident.RootProcessName, incident.RootExecutablePath,
                $"Incident={incident.IncidentId}; ActorIdentity={incident.ActorIdentityStatus}; " +
                $"HeuristicScore={incident.RiskScore}; RequestedAction=None; PerformedAction=None; " +
                "ProcessTerminated=false; FileQuarantined=false; ContainmentPerformed=false",
                AuditResult.Success, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            LogObservationFailure(exception, "Behavior observation audit persistence failed; no action was performed.");
        }
    }

    private void LogObservationFailure(Exception exception, string message)
    {
        try
        {
            if (_logger != null) _logger.LogWarning(exception, "{ObservationFailure}", message);
            else Trace.TraceWarning("{0} {1}", message, exception);
        }
        catch (Exception loggingException)
        {
            Debug.WriteLine($"Behavior observation logging failed: {loggingException}; original error: {exception}");
        }
    }

    private static SecurityIncident CopyIncident(SecurityIncident source) => new()
    {
        IncidentId = source.IncidentId,
        CreatedAt = source.CreatedAt,
        Title = source.Title,
        ThreatName = source.ThreatName,
        RootPid = source.RootPid,
        RootProcessName = source.RootProcessName,
        RootExecutablePath = source.RootExecutablePath,
        RootHashSha256 = source.RootHashSha256,
        RootProcessStartTimeUtc = source.RootProcessStartTimeUtc,
        ActorIdentityStatus = source.ActorIdentityStatus,
        RiskScore = source.RiskScore,
        RiskLevel = source.RiskLevel,
        Status = source.Status,
        ActionTaken = source.ActionTaken,
        Evidences = source.Evidences.Select(e => new BehaviorEvidence
        {
            EvidenceId = e.EvidenceId,
            Timestamp = e.Timestamp,
            Type = e.Type,
            Source = e.Source,
            Target = e.Target,
            Explanation = e.Explanation,
            Confidence = e.Confidence,
            Severity = e.Severity,
            SourceEventId = e.SourceEventId,
            OriginatingEventId = e.OriginatingEventId,
            ObservationSource = e.ObservationSource
        }).ToList(),
        Timeline = source.Timeline.ToList(),
        HumanExplanation = source.HumanExplanation,
        RecommendedUserAction = source.RecommendedUserAction
    };
}
