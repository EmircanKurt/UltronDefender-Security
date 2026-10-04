using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime;

/// <summary>
/// Records bounded, review-only behavior observations. Reported event types, commands, scores,
/// and process metadata cannot authorize process termination, file access, or quarantine.
/// </summary>
public partial class BehaviorEngine : IBehaviorEngine, IDisposable
{
    private const int MaximumSessions = 256;
    private const int MaximumEventsPerSession = 64;
    private const int MaximumIncidents = 256;
    private const int MaximumOriginatingEvents = 4096;
    private const int MaximumMetadataLength = 2048;
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(1);
    private readonly ILogger<BehaviorEngine>? _logger;
    private readonly IAuditLogService? _auditLogService;
    private readonly IProcessLineageTracker _lineageTracker;
    private readonly IAttackChainCorrelator _attackChainCorrelator;
    private readonly IProcessInjectionDetector _injectionDetector;
    private readonly Dictionary<string, ProcessBehaviorSession> _sessions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SecurityIncident> _incidents = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTime> _originatingEvents = new(StringComparer.Ordinal);
    private readonly object _lock = new();
    private readonly Timer _cleanupTimer;
    private bool _disposed;

    /// <summary>Raised for an observation snapshot; each subscriber receives an isolated copy.</summary>
    public event Action<SecurityIncident>? OnIncidentCreated;

    /// <summary>
    /// Retains subscription compatibility. This observation-only engine never raises containment events.
    /// </summary>
    public event Action<string, string>? OnThreatContained { add { } remove { } }

    /// <summary>Gets the legacy tracker for compatibility; it is not an attribution or decision source here.</summary>
    public IProcessLineageTracker LineageTracker => _lineageTracker;

    /// <summary>Gets the legacy correlator; PID-only results never influence this engine's observations.</summary>
    public IAttackChainCorrelator AttackChainCorrelator => _attackChainCorrelator;

    /// <summary>Gets the optional legacy injection analyzer without treating its result as action authority.</summary>
    public IProcessInjectionDetector InjectionDetector => _injectionDetector;

    /// <summary>
    /// Preserves existing dependencies and optionally records observation audits. Quarantine is
    /// deliberately unused; this API receives no authoritative evidence or mutation capability.
    /// </summary>
    public BehaviorEngine(
        IQuarantineService? quarantineService = null,
        IProcessLineageTracker? lineageTracker = null,
        IAttackChainCorrelator? attackChainCorrelator = null,
        IProcessInjectionDetector? injectionDetector = null,
        ILogger<BehaviorEngine>? logger = null,
        IAuditLogService? auditLogService = null)
    {
        _ = quarantineService;
        _lineageTracker = lineageTracker ?? new AegisPC.Security.Behavior.ProcessLineageTracker();
        _attackChainCorrelator = attackChainCorrelator ?? new AegisPC.Security.Behavior.AttackChainCorrelator(_lineageTracker);
        _injectionDetector = injectionDetector ?? new AegisPC.Security.Behavior.ProcessInjectionDetector();
        _logger = logger;
        _auditLogService = auditLogService;
        _cleanupTimer = new Timer(CleanupSessions, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    /// <summary>
    /// Records an inert observation and isolates subscriber or audit failures. Missing creation
    /// identity remains Unknown; neither event time nor a matching PID establishes process identity.
    /// </summary>
    public async Task ProcessEventAsync(BehaviorEvent e, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (e == null) return;
        SecurityIncident? incident;
        lock (_lock)
        {
            if (_disposed) return;
            var now = DateTime.UtcNow;
            TrimState(now);
            var observation = CopyEvent(e);
            if (!TryRememberOrigin(observation, now)) return;
            var session = GetOrCreateSession(observation, now);
            session.LastActivityAt = now;
            session.Events.Add(observation);
            if (session.Events.Count > MaximumEventsPerSession)
                session.Events.RemoveRange(0, session.Events.Count - MaximumEventsPerSession);
            var evaluation = EvaluateObservations(session, now);
            session.CurrentRiskScore = evaluation.Score;
            if (evaluation.Evidences.Count == 0 || evaluation.Signature == session.PublishedFeatureSignature) return;
            session.PublishedFeatureSignature = evaluation.Signature;
            incident = CreateObservationIncident(session, evaluation, now);
            _incidents[incident.IncidentId] = incident;
            TrimIncidents();
        }
        PublishObservation(incident);
        await RecordObservationAsync(incident, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Gets detached active observation snapshots; reviewed observations are excluded.</summary>
    public Task<List<SecurityIncident>> GetActiveIncidentsAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_lock)
            return Task.FromResult(_incidents.Values.Where(i => i.Status != "Reviewed")
                .OrderByDescending(i => i.CreatedAt).Select(CopyIncident).ToList());
    }

    /// <summary>Returns a detached observation snapshot, or null when its bounded retention has expired.</summary>
    public Task<SecurityIncident?> GetIncidentByIdAsync(string incidentId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_lock)
            return Task.FromResult(_incidents.TryGetValue(incidentId, out var incident) ? CopyIncident(incident) : null);
    }

    /// <summary>
    /// Acknowledges review of a retained observation. The compatibility name does not mean
    /// that a process was stopped, a file was removed, or malware was remediated.
    /// </summary>
    public Task<bool> RemediateIncidentAsync(string incidentId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_lock)
        {
            if (!_incidents.TryGetValue(incidentId, out var incident)) return Task.FromResult(false);
            incident.Status = "Reviewed";
            incident.ActionTaken = "None";
            return Task.FromResult(true);
        }
    }

    /// <summary>Stops retention cleanup and releases observation state without touching any OS process or file.</summary>
    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            _sessions.Clear();
            _incidents.Clear();
            _originatingEvents.Clear();
        }
        _cleanupTimer.Dispose();
    }
}
