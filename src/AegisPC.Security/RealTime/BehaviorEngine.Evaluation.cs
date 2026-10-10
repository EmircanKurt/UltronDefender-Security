using System;
using System.Collections.Generic;
using System.Linq;
using AegisPC.Core.Models;

namespace AegisPC.Security.RealTime;

public partial class BehaviorEngine
{
    private sealed record ObservationEvaluation(int Score, List<BehaviorEvidence> Evidences, string Signature);

    private static ObservationEvaluation EvaluateObservations(ProcessBehaviorSession session, DateTime now)
    {
        var observations = session.Events
            .Where(e => e.Timestamp.Kind == DateTimeKind.Utc &&
                e.Timestamp >= now - ObservationWindow && e.Timestamp <= now.AddMinutes(1))
            .Select(e => (Event: e, Feature: GetFeature(e.EventType)))
            .Where(item => item.Feature.Score > 0)
            .GroupBy(item => item.Feature.Type, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToList();
        var evidence = observations.Select(item => new BehaviorEvidence
        {
            Timestamp = item.Event.Timestamp,
            Type = item.Feature.Type,
            Source = item.Event.ProcessName,
            Target = item.Event.TargetResource,
            SourceEventId = item.Event.EventId,
            OriginatingEventId = item.Event.OriginatingEventId ?? item.Event.EventId,
            ObservationSource = item.Event.Source,
            Explanation = $"Reported {item.Event.EventType}; collector={item.Event.Source}; " +
                $"event={item.Event.EventId}; origin={item.Event.OriginatingEventId}; " +
                $"reported PID={item.Event.ProcessId}; reported path={item.Event.ExecutablePath}; " +
                $"target={item.Event.TargetResource}; details={item.Event.Details}; " +
                "operation outcome and malicious intent are unverified.",
            Severity = item.Feature.Score,
            Confidence = 0.25
        }).ToList();
        int score = Math.Min(65, observations.Sum(item => item.Feature.Score));
        string signature = string.Join("|", observations.Select(item => item.Feature.Type).OrderBy(type => type, StringComparer.Ordinal));
        return new ObservationEvaluation(score, evidence, signature);
    }

    private static (string Type, int Score) GetFeature(BehaviorEventType eventType) => eventType switch
    {
        BehaviorEventType.ChildProcessSpawn => ("ExecutionObservation", 10),
        BehaviorEventType.RegistryPersistence => ("PersistenceObservation", 20),
        BehaviorEventType.BrowserDataAccess or BehaviorEventType.CredentialAccessAttempt => ("CredentialAccessObservation", 20),
        BehaviorEventType.SuspiciousNetworkConnect => ("NetworkObservation", 15),
        BehaviorEventType.FileEncryptionAttempt => ("FileTransformationObservation", 30),
        BehaviorEventType.ShadowCopyDeletion => ("RecoveryDataObservation", 30),
        BehaviorEventType.AmsiBypassAttempt => ("DefenseEvasionObservation", 25),
        BehaviorEventType.ProcessInjection => ("ProcessMemoryObservation", 25),
        _ => (string.Empty, 0)
    };
}
