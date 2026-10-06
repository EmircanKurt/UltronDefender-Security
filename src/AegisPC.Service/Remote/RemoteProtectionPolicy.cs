using System.Net;
using AegisPC.Contracts.Protection;

namespace AegisPC.Service.Remote;

/// <summary>Bounded deterministic AFK/RDP review policy. It never calls firewall, disconnect, scan, isolation or reboot APIs.</summary>
public sealed class RemoteProtectionPolicy
{
    private static readonly TimeSpan Freshness = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan AwayThreshold = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan SuggestedLease = TimeSpan.FromMinutes(10);
    private const int MaximumTargets = 256;
    private const int MaximumSeenEvents = 2048;
    private readonly Dictionary<string, DateTime> _seen = new(StringComparer.Ordinal);
    private readonly Dictionary<(string Address, string Sid), FailureHistory> _targets = new();
    private readonly object _gate = new();
    private DateTime _lastEvaluationUtc;

    /// <summary>Combines fresh source metadata with five distinct failures in two minutes into non-enforcing advice.</summary>
    public RemoteProtectionSnapshot Evaluate(DateTime utcNow, ConsolePresenceObservation console, RdpLogonBatch batch)
    {
        ArgumentNullException.ThrowIfNull(console);
        ArgumentNullException.ThrowIfNull(batch);
        lock (_gate)
        {
            if (utcNow == default || utcNow.Kind != DateTimeKind.Utc)
                return new() { CapturedAtUtc = utcNow, ConsoleAvailability = SecurityObservationAvailability.Unavailable,
                    LogonAvailability = SecurityObservationAvailability.Unavailable,
                    Limitations = ["A non-UTC or absent clock cannot establish current remote-protection observations."] };
            var limitations = (batch.Limitations ?? []).Take(12).ToList();
            if (!string.IsNullOrWhiteSpace(console.Limitation)) limitations.Add(console.Limitation);
            limitations.Add("ObservationOnly: no RDP connection is blocked, approved or disconnected.");
            limitations.Add("Outbound relay remote-control applications are outside this RDP observation source.");
            if (_lastEvaluationUtc != default && utcNow < _lastEvaluationUtc)
            {
                _seen.Clear();
                _targets.Clear();
                limitations.Add("Clock moved backwards; remote review history was reset.");
            }
            _lastEvaluationUtc = utcNow;
            ExpireHistory(utcNow);
            bool consoleFresh = IsFresh(console.CapturedAtUtc, utcNow);
            LocalConsolePresence presence = ClassifyPresence(console, consoleFresh);
            if (!consoleFresh) limitations.Add("Physical-console observation is stale, absent or future-dated.");
            bool batchFresh = IsFresh(batch.CapturedAtUtc, utcNow);
            if (!batchFresh) limitations.Add("Remote-logon batch is stale, absent or future-dated.");
            if (batchFresh && batch.Availability is SecurityObservationAvailability.Available or SecurityObservationAvailability.Partial)
                foreach (var item in (batch.Events ?? []).Take(256))
                    if (item != null) RecordFailure(item, utcNow, limitations);
            if ((batch.Events?.Count ?? 0) > 256) limitations.Add("Remote-logon batch exceeded the per-refresh review budget.");
            return new()
            {
                CapturedAtUtc = utcNow,
                ConsolePresence = presence,
                ConsoleAvailability = consoleFresh ? console.Availability : SecurityObservationAvailability.Unavailable,
                LogonAvailability = batchFresh ? batch.Availability : SecurityObservationAvailability.Unavailable,
                WouldDenyNewRdpWhileAway = presence is LocalConsolePresence.Away or LocalConsolePresence.Locked or LocalConsolePresence.NoLocalSession,
                RepeatedFailureProposals = _targets.Values.Where(x => x.Proposal != null && x.Proposal.SuggestedUntilUtc > utcNow)
                    .Select(x => x.Proposal!).Take(64).ToArray(),
                LostEvents = Math.Max(0, batch.LostEvents),
                Limitations = limitations.Distinct(StringComparer.Ordinal).Take(16).ToArray()
            };
        }
    }

    private static bool IsFresh(DateTime captured, DateTime now) => captured != default && captured.Kind == DateTimeKind.Utc &&
        captured <= now && now - captured <= Freshness;

    private static LocalConsolePresence ClassifyPresence(ConsolePresenceObservation observation, bool fresh)
    {
        if (!fresh || observation.Availability != SecurityObservationAvailability.Available) return LocalConsolePresence.Unknown;
        if (!observation.SessionId.HasValue) return LocalConsolePresence.NoLocalSession;
        // A remote client's input must never establish physical presence or reset an AFK decision.
        if (observation.ClientProtocolType != 0 || !observation.IsLocked.HasValue) return LocalConsolePresence.Unknown;
        if (observation.IsLocked.Value) return LocalConsolePresence.Locked;
        if (!observation.IdleDuration.HasValue || observation.IdleDuration.Value < TimeSpan.Zero) return LocalConsolePresence.Unknown;
        return observation.IdleDuration.Value >= AwayThreshold ? LocalConsolePresence.Away : LocalConsolePresence.Present;
    }

    private void RecordFailure(RdpLogonObservation item, DateTime now, List<string> limitations)
    {
        string targetSid = item.TargetSid ?? string.Empty;
        if (!item.IsAuthenticationFailure || !item.IsRdpCorrelated || item.TimestampUtc == default ||
            item.TimestampUtc.Kind != DateTimeKind.Utc || item.TimestampUtc > now || now - item.TimestampUtc > FailureWindow || string.IsNullOrWhiteSpace(item.EventIdentity) ||
            item.EventIdentity.Length > 192 || targetSid.Length > 256 ||
            !IPAddress.TryParse(item.RemoteAddress, out var address) || IPAddress.IsLoopback(address)) return;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || _seen.ContainsKey(item.EventIdentity)) return;
        if (_seen.Count >= MaximumSeenEvents)
        {
            limitations.Add("Remote failure deduplication budget was reached; review history is incomplete.");
            return;
        }
        var key = (address.ToString(), targetSid);
        if (!_targets.TryGetValue(key, out var history))
        {
            if (_targets.Count >= MaximumTargets)
            {
                limitations.Add("Remote failure target budget was reached; review history is incomplete.");
                return;
            }
            history = new();
            _targets.Add(key, history);
        }
        _seen.Add(item.EventIdentity, item.TimestampUtc);
        history.Timestamps.RemoveAll(time => now - time > FailureWindow);
        history.Timestamps.Add(item.TimestampUtc);
        // Five timestamps suffice to preserve the threshold without unbounded per-source history.
        if (history.Timestamps.Count > 5) history.Timestamps.RemoveAt(0);
        if (history.Timestamps.Count >= 5 && (history.Proposal == null || history.Proposal.SuggestedUntilUtc <= now))
            history.Proposal = new()
            {
                RemoteAddress = key.Item1, TargetSid = key.Item2, DistinctFailures = history.Timestamps.Count,
                SuggestedUntilUtc = now + SuggestedLease
            };
    }

    private void ExpireHistory(DateTime now)
    {
        foreach (var key in _seen.Where(pair => now - pair.Value > FailureWindow).Select(pair => pair.Key).ToArray()) _seen.Remove(key);
        foreach (var pair in _targets.ToArray())
        {
            pair.Value.Timestamps.RemoveAll(time => now - time > FailureWindow);
            if (pair.Value.Proposal?.SuggestedUntilUtc <= now) pair.Value.Proposal = null;
            if (pair.Value.Timestamps.Count == 0 && pair.Value.Proposal == null) _targets.Remove(pair.Key);
        }
    }

    private sealed class FailureHistory
    {
        internal List<DateTime> Timestamps { get; } = [];
        internal RemoteDenialProposal? Proposal { get; set; }
    }
}

/// <summary>Combines inert, read-only adapters into a cached service snapshot; subscription ownership stays with the host.</summary>
public sealed class RemoteProtectionMonitor(IConsolePresenceObserver console, IRdpLogonObservationSource logons,
    RemoteProtectionPolicy policy) : IRemoteProtectionMonitor
{
    private RemoteProtectionSnapshot _snapshot = new()
    {
        Limitations = ["Remote observations have not started.", "Native RDP enforcement is not implemented."]
    };

    /// <inheritdoc />
    public RemoteProtectionSnapshot CurrentSnapshot => Volatile.Read(ref _snapshot);

    /// <inheritdoc />
    public RemoteProtectionSnapshot Refresh(DateTime utcNow)
    {
        var next = policy.Evaluate(utcNow, console.Capture(utcNow), logons.Drain(utcNow));
        Volatile.Write(ref _snapshot, next);
        return next;
    }
}
