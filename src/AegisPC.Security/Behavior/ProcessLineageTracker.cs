using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using AegisPC.Contracts.Behavior;

namespace AegisPC.Security.Behavior
{
    public class ProcessLineageTracker : IProcessLineageTracker
    {
        private readonly ConcurrentDictionary<int, ProcessNode> _processes = new();
        private readonly TimeSpan _nodeTtl = TimeSpan.FromMinutes(10);

        public void RegisterProcess(ProcessNode node)
        {
            if (node == null) return;
            CleanupStaleNodes();

            _processes[node.Pid] = node;
            if (node.ParentPid > 0 && _processes.TryGetValue(node.ParentPid, out var parentNode))
            {
                lock (parentNode.ChildPids)
                {
                    if (!parentNode.ChildPids.Contains(node.Pid))
                    {
                        parentNode.ChildPids.Add(node.Pid);
                    }
                }
            }
        }

        public void MarkTerminated(int pid)
        {
            if (_processes.TryGetValue(pid, out var node))
            {
                node.IsTerminated = true;
            }
        }

        public ProcessNode? GetProcess(int pid)
        {
            _processes.TryGetValue(pid, out var node);
            return node;
        }

        public IReadOnlyList<ProcessNode> GetAncestors(int pid)
        {
            var list = new List<ProcessNode>();
            if (!_processes.TryGetValue(pid, out var current)) return list;

            int parentPid = current.ParentPid;
            while (parentPid > 0 && _processes.TryGetValue(parentPid, out var parentNode))
            {
                list.Add(parentNode);
                if (parentNode.ParentPid <= 0 || parentNode.ParentPid == parentPid) break;
                parentPid = parentNode.ParentPid;
            }

            return list;
        }

        public IReadOnlyList<ProcessNode> GetDescendants(int pid)
        {
            var list = new List<ProcessNode>();
            if (_processes.TryGetValue(pid, out var rootNode))
            {
                CollectDescendants(rootNode, list);
            }
            return list;
        }

        private void CollectDescendants(ProcessNode current, List<ProcessNode> list)
        {
            lock (current.ChildPids)
            {
                foreach (int childPid in current.ChildPids)
                {
                    if (_processes.TryGetValue(childPid, out var childNode) && !list.Contains(childNode))
                    {
                        list.Add(childNode);
                        CollectDescendants(childNode, list);
                    }
                }
            }
        }

        public bool IsSuspiciousParentChild(int parentPid, int childPid, out string? reason)
        {
            reason = null;
            if (!_processes.TryGetValue(parentPid, out var parent) || !_processes.TryGetValue(childPid, out var child))
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
            foreach (var kvp in _processes)
            {
                if (kvp.Value.IsTerminated && kvp.Value.StartTimeUtc < threshold)
                {
                    _processes.TryRemove(kvp.Key, out _);
                }
            }
        }
    }
}
