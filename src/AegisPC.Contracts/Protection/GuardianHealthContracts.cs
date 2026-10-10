namespace AegisPC.Contracts.Protection;

/// <summary>Separates unknown/stale service health from verified malicious activity.</summary>
public enum GuardianHealthState { Unverified, Healthy, Degraded, MissingHeartbeat, Maintenance, Stopped }
/// <summary>Observed state only. A heartbeat alone cannot prove watcher continuity or vault ownership.</summary>
public sealed record GuardianHealthSnapshot(GuardianHealthState State, DateTimeOffset? LastHeartbeatUtc,
    int ConsecutiveMissingHeartbeats, int ActiveObservers, bool VaultOwnershipVerified, IReadOnlyList<string> Limitations);
/// <summary>Records bounded recovery recommendations; does not issue native SCM actions.</summary>
public interface IGuardianHealthMonitor
{
    /// <summary>Accepts an independently observed heartbeat and actual critical component health.</summary>
    void ObserveHeartbeat(int activeObservers, bool vaultOwnershipVerified);
    /// <summary>Returns the current state without attributing missing health to malware.</summary>
    GuardianHealthSnapshot Capture();
    /// <summary>Requests a limited recovery attempt only when missing health and cooldown permit it.</summary>
    bool TryReserveRestart();
    /// <summary>Suppresses recovery during a bounded, authorized maintenance/update/uninstall lease.</summary>
    void SetMaintenance(TimeSpan duration);
}
