using System;
using System.Linq;
using AegisPC.Core.Models;

namespace AegisPC.Security.RealTime;

public partial class BehaviorEngine
{
    private void CleanupSessions(object? state)
    {
        try
        {
            lock (_lock)
                if (!_disposed) TrimState(DateTime.UtcNow);
        }
        catch (Exception exception)
        {
            LogObservationFailure(exception, "Behavior observation retention cleanup failed.");
        }
    }

    private void TrimState(DateTime now)
    {
        var cutoff = now - SessionLifetime;
        foreach (var key in _sessions.Where(pair => pair.Value.LastActivityAt < cutoff).Select(pair => pair.Key).ToArray())
            _sessions.Remove(key);
        foreach (var key in _incidents.Where(pair => pair.Value.CreatedAt < cutoff).Select(pair => pair.Key).ToArray())
            _incidents.Remove(key);
        foreach (var key in _originatingEvents.Where(pair => pair.Value < cutoff).Select(pair => pair.Key).ToArray())
            _originatingEvents.Remove(key);
    }

    private bool TryRememberOrigin(BehaviorEvent observation, DateTime now)
    {
        var key = GetOriginKey(observation);
        if (_originatingEvents.ContainsKey(key)) return false;
        if (_originatingEvents.Count >= MaximumOriginatingEvents)
            _originatingEvents.Remove(_originatingEvents.MinBy(pair => pair.Value).Key);
        _originatingEvents.Add(key, now);
        return true;
    }

    private ProcessBehaviorSession GetOrCreateSession(BehaviorEvent observation, DateTime now)
    {
        bool hasIdentity = HasCreationIdentity(observation);
        string key = hasIdentity
            ? $"actor:{observation.ProcessId}:{observation.ProcessStartTimeUtc!.Value.Ticks}"
            : $"unknown:{GetOriginKey(observation)}";
        if (_sessions.TryGetValue(key, out var existing)) return existing;
        if (_sessions.Count >= MaximumSessions)
            _sessions.Remove(_sessions.MinBy(pair => pair.Value.LastActivityAt).Key);
        var session = new ProcessBehaviorSession
        {
            RootPid = hasIdentity ? observation.ProcessId : 0,
            RootProcessName = hasIdentity ? observation.ProcessName : "UnknownProcess",
            RootExecutablePath = hasIdentity ? observation.ExecutablePath : string.Empty,
            StartedAt = hasIdentity ? observation.ProcessStartTimeUtc!.Value : observation.Timestamp,
            LastActivityAt = now,
            HasCreationIdentity = hasIdentity
        };
        _sessions.Add(key, session);
        return session;
    }

    private static bool HasCreationIdentity(BehaviorEvent observation) =>
        observation.ProcessId > 4 &&
        observation.ProcessStartTimeUtc is DateTime created &&
        created.Kind == DateTimeKind.Utc && created > DateTime.UnixEpoch &&
        observation.Timestamp.Kind == DateTimeKind.Utc && created <= observation.Timestamp &&
        observation.Timestamp <= DateTime.UtcNow.AddMinutes(1);

    private void TrimIncidents()
    {
        if (_incidents.Count > MaximumIncidents)
            _incidents.Remove(_incidents.MinBy(pair => pair.Value.CreatedAt).Key);
    }

    private static string GetOriginKey(BehaviorEvent observation) =>
        $"{observation.Source.Length}:{observation.Source}:{observation.OriginatingEventId}";

    private static string BoundedText(string? value) =>
        string.IsNullOrEmpty(value) ? string.Empty : value[..Math.Min(value.Length, MaximumMetadataLength)];

    private static BehaviorEvent CopyEvent(BehaviorEvent source)
    {
        var eventId = BoundedText(source.EventId);
        if (string.IsNullOrEmpty(eventId)) eventId = Guid.NewGuid().ToString("N");
        return new BehaviorEvent
        {
            EventId = eventId,
            OriginatingEventId = string.IsNullOrWhiteSpace(source.OriginatingEventId)
                ? eventId : BoundedText(source.OriginatingEventId),
            Source = string.IsNullOrWhiteSpace(source.Source) ? "Unspecified" : BoundedText(source.Source),
            Timestamp = source.Timestamp,
            EventType = source.EventType,
            ProcessId = source.ProcessId,
            ProcessName = BoundedText(source.ProcessName),
            ExecutablePath = BoundedText(source.ExecutablePath),
            CommandLine = BoundedText(source.CommandLine),
            ParentProcessId = source.ParentProcessId,
            ParentProcessName = BoundedText(source.ParentProcessName),
            ProcessStartTimeUtc = source.ProcessStartTimeUtc,
            ParentProcessStartTimeUtc = source.ParentProcessStartTimeUtc,
            TargetResource = BoundedText(source.TargetResource),
            Details = BoundedText(source.Details),
            RiskWeight = 0 // Caller-supplied score cannot influence observation priority.
        };
    }
}
