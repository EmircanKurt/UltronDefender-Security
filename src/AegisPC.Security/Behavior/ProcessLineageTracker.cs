using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using AegisPC.Contracts.Behavior;

namespace AegisPC.Security.Behavior
{
    public class ProcessLineageTracker : IProcessLineageTracker
    {
        private const int MaxNodes = 4096;
        private const int MaxTraversal = 256;
        private readonly object _gate = new();
        private readonly Dictionary<int, ProcessNode> _processes = new();
        private readonly Dictionary<int, (int Pid, DateTime Started, string BootId)> _parents = new();
        private readonly TimeSpan _nodeTtl = TimeSpan.FromMinutes(10);
        public long EvictedNodes { get; private set; }

        /// <summary>Captures a detached generation. Older starts cannot replace a newer reused PID.</summary>
        public void RegisterProcess(ProcessNode node)
        {
            if (node == null || node.Pid <= 0 || node.StartTimeUtc == default) return;
            lock (_gate)
            {
                CleanupStaleNodes();
                if (_processes.TryGetValue(node.Pid, out var existing) &&
                    existing.StartTimeUtc > node.StartTimeUtc) return;
                if (existing != null && SameIdentity(existing, node)) return;
                _parents.Remove(node.Pid);
                _processes[node.Pid] = Copy(node);
                if (node.ParentPid != node.Pid && _processes.TryGetValue(node.ParentPid, out var parent) &&
                    !parent.IsTerminated && parent.StartTimeUtc <= node.StartTimeUtc && parent.BootId == node.BootId)
                    _parents[node.Pid] = (parent.Pid, parent.StartTimeUtc, parent.BootId);
                while (_processes.Count > MaxNodes)
                {
                    int oldest = _processes.Values.MinBy(x => x.StartTimeUtc)!.Pid;
                    _processes.Remove(oldest);
                    _parents.Remove(oldest);
                    EvictedNodes++;
                }
            }
        }

        public void MarkTerminated(int pid) => MarkTerminatedAt(pid, DateTime.UtcNow);

        /// <summary>Rejects a delayed exit preceding the current generation's creation time.</summary>
        public void MarkTerminatedAt(int pid, DateTime eventUtc)
        {
            lock (_gate)
                if (_processes.TryGetValue(pid, out var node) && eventUtc >= node.StartTimeUtc)
                    node.IsTerminated = true;
        }

        public ProcessNode? GetProcess(int pid)
        {
            lock (_gate) return _processes.TryGetValue(pid, out var node) ? Copy(node) : null;
        }

        /// <summary>Bounded iterative traversal; frozen parent generations prevent PID-reuse links.</summary>
        public IReadOnlyList<ProcessNode> GetAncestors(int pid)
        {
            lock (_gate)
            {
                var list = new List<ProcessNode>();
                var visited = new HashSet<int> { pid };
                while (list.Count < MaxTraversal && _parents.TryGetValue(pid, out var identity) &&
                    visited.Add(identity.Pid) && _processes.TryGetValue(identity.Pid, out var parent) &&
                    parent.StartTimeUtc == identity.Started && parent.BootId == identity.BootId)
                {
                    list.Add(Copy(parent));
                    pid = parent.Pid;
                }
                return list;
            }
        }

        /// <summary>No recursion or nested node locks; caps a malformed or very large tree.</summary>
        public IReadOnlyList<ProcessNode> GetDescendants(int pid)
        {
            lock (_gate)
            {
                var list = new List<ProcessNode>();
                var visited = new HashSet<int> { pid };
                var pending = new Queue<int>();
                pending.Enqueue(pid);
                while (pending.Count > 0 && list.Count < MaxTraversal)
                {
                    int current = pending.Dequeue();
                    if (!_processes.TryGetValue(current, out var parent)) continue;
                    foreach (var child in _parents.Where(x => x.Value.Pid == current).ToArray())
                    {
                        if (!visited.Add(child.Key) || !_processes.TryGetValue(child.Key, out var node) ||
                            child.Value.Started != parent.StartTimeUtc || child.Value.BootId != parent.BootId) continue;
                        list.Add(Copy(node));
                        pending.Enqueue(child.Key);
                        if (list.Count >= MaxTraversal) break;
                    }
                }
                return list;
            }
        }

        private static bool SameIdentity(ProcessNode left, ProcessNode right) =>
            left.Pid == right.Pid && left.StartTimeUtc == right.StartTimeUtc && left.BootId == right.BootId;

        private static ProcessNode Copy(ProcessNode n) => new()
        {
            Pid = n.Pid, ParentPid = n.ParentPid, ProcessName = n.ProcessName, ExecutablePath = n.ExecutablePath,
            CommandLine = n.CommandLine, StartTimeUtc = n.StartTimeUtc, BootId = n.BootId, UserContext = n.UserContext,
            IntegrityLevel = n.IntegrityLevel, IsTerminated = n.IsTerminated
        };

        public bool IsSuspiciousParentChild(int parentPid, int childPid, out string? reason)
        {
            reason = null;
            var parent = GetProcess(parentPid);
            var child = GetProcess(childPid);
            if (parent == null || child == null || !GetAncestors(childPid).Any(x => SameIdentity(x, parent)))
            {
                return false;
            }

            return IsSuspiciousSpawn(parent, child, out reason);
        }

        public bool IsSuspiciousSpawn(ProcessNode parent, ProcessNode child, out string? reason)
        {
            reason = null;
            string pName = parent.ProcessName.ToLowerInvariant();
            string cName = child.ProcessName.ToLowerInvariant();

            // Fake Svchost (must be spawned by services.exe)
            if (cName.Contains("svchost.exe") && !pName.Contains("services.exe"))
            {
                reason = $"Sahte Alt Sistem Taklidi: svchost.exe ebeveyni {parent.ProcessName} olamaz";
                return true;
            }

            // Fake Lsass (must be spawned by wininit.exe)
            if (cName.Contains("lsass.exe") && !pName.Contains("wininit.exe"))
            {
                reason = $"Sahte LSASS Süreci Taklidi: lsass.exe ebeveyni {parent.ProcessName} olamaz";
                return true;
            }

            // Office -> Script Engine or cmd
            if ((pName.Contains("winword") || pName.Contains("excel") || pName.Contains("powerpnt") || pName.Contains("outlook")) &&
                (cName.Contains("powershell") || cName.Contains("cmd") || cName.Contains("mshta") || cName.Contains("cscript") || cName.Contains("wscript") || cName.Contains("certutil")))
            {
                reason = $"Şüpheli Office Makro Süreç Türetmesi: {parent.ProcessName} -> {child.ProcessName}";
                return true;
            }

            // Web Browser -> CMD/PowerShell
            if ((pName.Contains("chrome") || pName.Contains("msedge") || pName.Contains("brave") || pName.Contains("firefox")) &&
                (cName.Contains("powershell") || cName.Contains("cmd") || cName.Contains("bitsadmin")))
            {
                reason = $"Şüpheli Tarayıcı RCE / LOLBin Türetmesi: {parent.ProcessName} -> {child.ProcessName}";
                return true;
            }

            return false;
        }

        private void CleanupStaleNodes()
        {
            var threshold = DateTime.UtcNow - _nodeTtl;
            foreach (var kvp in _processes.ToArray())
            {
                if (kvp.Value.IsTerminated && kvp.Value.StartTimeUtc < threshold)
                {
                    _processes.Remove(kvp.Key);
                    _parents.Remove(kvp.Key);
                }
            }
        }
    }
}
