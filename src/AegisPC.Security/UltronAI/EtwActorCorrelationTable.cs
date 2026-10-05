using AegisPC.Contracts.Protection;

namespace AegisPC.Security.UltronAI;

/// <summary>
/// Bounded ETW process/thread-generation mapping. A file event header PID, watcher callback or lock
/// owner cannot substitute for an observed live thread. Missing/rundown/lost relations stay unknown.
/// </summary>
public sealed class EtwActorCorrelationTable
{
    private readonly Dictionary<int, BehaviorProcessIdentity> _processes = new();
    private readonly Dictionary<int, (BehaviorProcessIdentity Actor, DateTimeOffset Started)> _threads = new();
    private const int MaxProcesses = 4096, MaxThreads = 8192;
    private readonly object _gate = new();
    /// <summary>Cumulative writes lacking a live observed thread/process generation.</summary>
    public long UnattributedWrites { get; private set; }
    /// <summary>Mappings discarded at capacity; eviction is a coverage limitation, not an attack.</summary>
    public long MappingEvictions { get; private set; }

    /// <summary>Records a real start; stale/duplicate identities cannot replace a newer PID generation.</summary>
    public void ProcessStarted(BehaviorProcessIdentity actor)
    {
        lock (_gate)
        {
            if (actor.Pid <= 4 || actor.StartedAtUtc <= DateTimeOffset.UnixEpoch || string.IsNullOrWhiteSpace(actor.BootId)) return;
            if (_processes.TryGetValue(actor.Pid, out var current) && current.StartedAtUtc >= actor.StartedAtUtc) return;
            foreach (var key in _threads.Where(x => x.Value.Actor.Pid == actor.Pid).Select(x => x.Key).ToArray()) _threads.Remove(key);
            if (_processes.Count >= MaxProcesses && !_processes.ContainsKey(actor.Pid))
            {
                var oldest = _processes.Values.MinBy(x => x.StartedAtUtc)!;
                RemoveProcess(oldest.Pid); MappingEvictions++;
            }
            _processes[actor.Pid] = actor;
        }
    }
    /// <summary>Removes only a generation old enough to own the exit event.</summary>
    public void ProcessStopped(int pid, DateTimeOffset time)
    {
        lock (_gate) if (_processes.TryGetValue(pid, out var p) && time >= p.StartedAtUtc) RemoveProcess(pid);
    }
    /// <summary>Binds an observed thread start to an existing process generation; missing relations remain unknown.</summary>
    public void ThreadStarted(int tid, int pid, DateTimeOffset time)
    {
        lock (_gate)
        {
            if (tid <= 0 || !_processes.TryGetValue(pid, out var actor) || time < actor.StartedAtUtc) return;
            if (_threads.TryGetValue(tid, out var current) && current.Started >= time) return;
            if (_threads.Count >= MaxThreads && !_threads.ContainsKey(tid))
            { _threads.Remove(_threads.MinBy(x => x.Value.Started).Key); MappingEvictions++; }
            _threads[tid] = (actor, time);
        }
    }
    /// <summary>Rejects delayed exit events preceding a reused thread's current start.</summary>
    public void ThreadStopped(int tid, DateTimeOffset time)
    {
        lock (_gate) if (_threads.TryGetValue(tid, out var thread) && time >= thread.Started) _threads.Remove(tid);
    }
    /// <summary>Uses File I/O TTID, never the header PID; unresolved writes increment a health counter.</summary>
    public BehaviorProcessIdentity? ResolveWriter(int tid, DateTimeOffset time)
    {
        lock (_gate)
        {
            if (_threads.TryGetValue(tid, out var t) && time >= t.Started &&
                _processes.TryGetValue(t.Actor.Pid, out var p) && p == t.Actor) return p;
            UnattributedWrites++; return null;
        }
    }
    /// <summary>Discards all actor relationships after event loss instead of preserving potentially stale attribution.</summary>
    public void InvalidateContinuity() { lock (_gate) { _processes.Clear(); _threads.Clear(); } }
    private void RemoveProcess(int pid)
    {
        _processes.Remove(pid);
        foreach (var tid in _threads.Where(x => x.Value.Actor.Pid == pid).Select(x => x.Key).ToArray()) _threads.Remove(tid);
    }
}

