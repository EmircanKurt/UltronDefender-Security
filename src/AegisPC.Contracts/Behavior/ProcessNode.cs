using System;
using System.Collections.Generic;

namespace AegisPC.Contracts.Behavior
{
    /// <summary>
    /// Süreç soyağacındaki (Process Lineage Tree) bir süreç düğümü.
    /// </summary>
    public class ProcessNode
    {
        public int Pid { get; set; }
        public int ParentPid { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ExecutablePath { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
        public DateTime StartTimeUtc { get; set; } = DateTime.UtcNow;
        public string UserContext { get; set; } = string.Empty;
        public string IntegrityLevel { get; set; } = "Medium";
        public bool IsTerminated { get; set; }
        public List<int> ChildPids { get; set; } = new();

        public override string ToString() => $"[PID: {Pid}, Parent: {ParentPid}] {ProcessName} ({CommandLine})";
    }
}
