using AegisPC.Contracts.Protection;

namespace AegisPC.Security.UltronAI;

/// <summary>5-second/three-miss health policy with bounded recovery. Missing heartbeat is never attack evidence.</summary>
public sealed class GuardianHealthMonitor : IGuardianHealthMonitor
{
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly Queue<DateTimeOffset> _attempts = new();
    private DateTimeOffset? _heartbeat;
    private DateTimeOffset? _maintenanceUntil;
    private DateTimeOffset? _faultSince;
    private int _observers;
    private bool _vault;
    /// <summary>Creates an initially unverified monitor without starting a timer or a Windows service.</summary>
    public GuardianHealthMonitor(TimeProvider? time = null) => _time = time ?? TimeProvider.System;
    /// <summary>Updates observed components; it does not treat desired settings as active observers.</summary>
    public void ObserveHeartbeat(int activeObservers, bool vaultOwnershipVerified)
    {
        lock (_gate)
        { _heartbeat = _time.GetUtcNow(); _observers = Math.Max(0, activeObservers); _vault = vaultOwnershipVerified; _faultSince = null; }
    }
    /// <summary>Maintains explicit component gaps even with a fresh heartbeat.</summary>
    public GuardianHealthSnapshot Capture()
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            var limits = new List<string>();
            int missed = _heartbeat == null ? 0 : (int)Math.Min(int.MaxValue, Math.Max(0, (now - _heartbeat.Value).TotalSeconds / 5));
            bool fresh = _heartbeat.HasValue && _heartbeat <= now && missed < 3;
            int observers = fresh ? _observers : 0;
            bool vault = fresh && _vault;
            if (!fresh) limits.Add("CoreHealthLeaseUnavailableOrExpired");
            if (observers == 0) limits.Add("NoCriticalObserversVerified");
            if (!vault) limits.Add("ExclusiveVaultOwnershipNotVerified");
            var state = _maintenanceUntil > now ? GuardianHealthState.Maintenance : _heartbeat == null || _heartbeat > now ? GuardianHealthState.Unverified :
                missed >= 3 ? GuardianHealthState.MissingHeartbeat : missed > 0 || limits.Count != 0 ? GuardianHealthState.Degraded : GuardianHealthState.Healthy;
            return new(state, _heartbeat, missed, observers, vault, limits.AsReadOnly());
        }
    }
    /// <summary>Recommends at most three attempts per ten minutes, with 5/15/60-second cooldowns. No restart is executed here.</summary>
    public bool TryReserveRestart()
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            if (Capture().State != GuardianHealthState.MissingHeartbeat) return false;
            _faultSince ??= now;
            while (_attempts.TryPeek(out var oldest) && now - oldest >= TimeSpan.FromMinutes(10)) _attempts.Dequeue();
            if (_attempts.Count >= 3) return false;
            var baseline = _attempts.Count == 0 ? _faultSince.Value : _attempts.Last();
            int delay = _attempts.Count switch { 0 => 5, 1 => 15, _ => 60 };
            if (now - baseline < TimeSpan.FromSeconds(delay)) return false;
            _attempts.Enqueue(now);
            return true;
        }
    }
    /// <summary>Accepts only a positive, bounded maintenance lease from an authorized host adapter.</summary>
    public void SetMaintenance(TimeSpan duration)
    {
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromMinutes(30)) throw new ArgumentOutOfRangeException(nameof(duration));
        lock (_gate) { _maintenanceUntil = _time.GetUtcNow() + duration; _faultSince = null; }
    }
}
