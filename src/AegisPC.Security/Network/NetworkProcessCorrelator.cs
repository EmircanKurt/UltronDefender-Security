using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Network;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Network;

/// <summary>Bounded, lifetime-aware network review. Names and periodicity cannot prove malicious activity.</summary>
public sealed class NetworkProcessCorrelator : INetworkProcessCorrelator, IWfpTelemetryEngine
{
    private const int Capacity = 4096;
    private static readonly TimeSpan Retention = TimeSpan.FromMinutes(5);
    private readonly Dictionary<string, NetworkFlowEvent> _flows = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly ILogger<NetworkProcessCorrelator>? _logger;
    private readonly TimeProvider _time;
    private long _dropped;

    /// <summary>Publishes frozen observations; it never executes containment.</summary>
    public event Action<NetworkFlowEvent>? OnFlowRecorded;
    /// <summary>Counts invalid or capacity-dropped input, not confirmed OS event loss.</summary>
    public long DroppedObservations { get { lock (_gate) return _dropped; } }
    /// <summary>Creates an inert bounded history with an injectable clock.</summary>
    public NetworkProcessCorrelator(ILogger<NetworkProcessCorrelator>? logger = null, TimeProvider? time = null)
    { _logger = logger; _time = time ?? TimeProvider.System; }

    /// <summary>Deduplicates events, freezes mutable input and rejects stale/future timestamps.</summary>
    public void IngestNetworkFlow(NetworkFlowEvent flow)
    {
        if (flow == null) return;
        NetworkFlowEvent frozen;
        lock (_gate)
        {
            Prune();
            if (!ValidObservation(flow)) { _dropped++; return; }
            if (_flows.ContainsKey(flow.EventId)) return;
            if (_flows.Count >= Capacity) { _dropped++; return; }
            frozen = Copy(flow);
            _flows.Add(frozen.EventId, frozen);
        }
        if (OnFlowRecorded == null) return;
        foreach (Action<NetworkFlowEvent> subscriber in OnFlowRecorded.GetInvocationList())
        {
            try { subscriber(Copy(frozen)); }
            catch (Exception ex) { _logger?.LogWarning(ex, "Network observation subscriber failed"); }
        }
    }

    /// <summary>Ranks periodic traffic for review only, using the same process lifetime, endpoint, port and protocol.</summary>
    public NetworkConnectionVerdict CorrelateFlow(NetworkFlowEvent flow)
    {
        var verdict = new NetworkConnectionVerdict
        { ThreatTitle = "No confirmed network threat", Explanation = "Observational analysis is not a clean-file or containment verdict." };
        if (flow == null || !ValidObservation(flow)) { verdict.Explanation = "Network observation unavailable or stale."; return verdict; }
        verdict.IsActorIdentityKnown = HasLifetime(flow);
        if (!verdict.IsActorIdentityKnown || NetworkAddressScope.IsLocalOrPrivate(flow.RemoteAddress)) return verdict;
        NetworkFlowEvent[] history;
        lock (_gate)
        {
            Prune();
            history = _flows.Values.Where(f => SameActorAndEndpoint(f, flow))
                .Where(f => f.TimestampUtc <= flow.TimestampUtc).OrderBy(f => f.TimestampUtc).ToArray();
        }
        if (history.Length < 4) return verdict;
        double[] intervals = history.Zip(history.Skip(1), (a, b) => (b.TimestampUtc - a.TimestampUtc).TotalSeconds).ToArray();
        double average = intervals.Average();
        double deviation = Math.Sqrt(intervals.Select(x => Math.Pow(x - average, 2)).Average());
        if (average <= 0.5 || average >= 120 || deviation >= 2) return verdict;
        verdict.HasPeriodicPattern = true;
        verdict.IsSuspicious = true;
        verdict.RiskScore = 25;
        verdict.ThreatTitle = "Periodic network activity: review suggested";
        verdict.Explanation = "Updates, backups and telemetry can also be periodic. Maliciousness is not confirmed.";
        verdict.Evidences.Add(new SecurityEvidence
        {
            Category = EvidenceCategory.BehaviorNetwork, RuleName = "NET_PERIODIC_ACTIVITY_REVIEW",
            ScoreContribution = 25, Confidence = EvidenceConfidence.Low,
            Description = $"Same-lifetime connections repeat at {average:F1}s intervals (deviation {deviation:F1}s); not C2 proof."
        });
        return verdict;
    }

    /// <summary>Returns diagnostic history only; mixed PID lifetimes from this view must never authorize an action.</summary>
    public IReadOnlyList<NetworkFlowEvent> GetProcessFlowHistory(int pid, TimeSpan window)
    {
        if (window <= TimeSpan.Zero) return Array.Empty<NetworkFlowEvent>();
        var cutoff = _time.GetUtcNow().UtcDateTime - (window > Retention ? Retention : window);
        lock (_gate) { Prune(); return _flows.Values.Where(f => f.ProcessId == pid && f.TimestampUtc >= cutoff).OrderBy(f => f.TimestampUtc).Select(Copy).ToArray(); }
    }

    private bool ValidObservation(NetworkFlowEvent flow)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        return !string.IsNullOrWhiteSpace(flow.EventId) && flow.EventId.Length <= 128 &&
            flow.ProcessId > 0 && flow.TimestampUtc.Kind == DateTimeKind.Utc &&
            flow.TimestampUtc <= now && flow.TimestampUtc >= now - Retention &&
            flow.RemotePort is >= 0 and <= 65535 && flow.LocalPort is >= 0 and <= 65535 &&
            System.Net.IPAddress.TryParse(flow.RemoteAddress, out _) && flow.ProcessName.Length <= 512 &&
            flow.ExecutablePath.Length <= 32768 && flow.BootId.Length <= 128;
    }
    private static bool HasLifetime(NetworkFlowEvent flow) => flow.ProcessStartedAtUtc is { Kind: DateTimeKind.Utc } start &&
        start <= flow.TimestampUtc && !string.IsNullOrWhiteSpace(flow.BootId);
    private static bool SameActorAndEndpoint(NetworkFlowEvent a, NetworkFlowEvent b) => HasLifetime(a) &&
        a.ProcessId == b.ProcessId && a.ProcessStartedAtUtc == b.ProcessStartedAtUtc && a.BootId == b.BootId &&
        a.RemoteAddress == b.RemoteAddress && a.RemotePort == b.RemotePort && a.Protocol == b.Protocol && a.Direction == b.Direction;
    private void Prune()
    {
        var cutoff = _time.GetUtcNow().UtcDateTime - Retention;
        foreach (string id in _flows.Where(x => x.Value.TimestampUtc < cutoff).Select(x => x.Key).ToArray()) _flows.Remove(id);
    }
    private static NetworkFlowEvent Copy(NetworkFlowEvent f) => new()
    {
        EventId = f.EventId, ProcessId = f.ProcessId, ProcessStartedAtUtc = f.ProcessStartedAtUtc, BootId = f.BootId,
        ProcessName = f.ProcessName, ExecutablePath = f.ExecutablePath, Direction = f.Direction, Protocol = f.Protocol,
        LocalAddress = f.LocalAddress, LocalPort = f.LocalPort, RemoteAddress = f.RemoteAddress, RemotePort = f.RemotePort,
        DestinationDomain = f.DestinationDomain, BytesSent = f.BytesSent, BytesReceived = f.BytesReceived, TimestampUtc = f.TimestampUtc
    };
}
