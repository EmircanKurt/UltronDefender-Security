using System.Collections.Generic;

namespace AegisPC.Contracts.Behavior
{
    /// <summary>
    /// Windows süreçlerinin ebeveyn-çocuk soyağacını (Parent-Child Lineage) izleyen ve
    /// anormal/zararlı süreç türetmelerini tespit eden izleyici arayüzü.
    /// </summary>
    public interface IProcessLineageTracker
    {
        void RegisterProcess(ProcessNode node);
        void MarkTerminated(int pid);
        ProcessNode? GetProcess(int pid);
        IReadOnlyList<ProcessNode> GetAncestors(int pid);
        IReadOnlyList<ProcessNode> GetDescendants(int pid);
        bool IsSuspiciousParentChild(int parentPid, int childPid, out string? reason);
        bool IsSuspiciousSpawn(ProcessNode parent, ProcessNode child, out string? reason);
    }
}
