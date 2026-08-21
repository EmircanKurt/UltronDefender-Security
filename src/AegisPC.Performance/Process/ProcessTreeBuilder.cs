using System.Collections.Generic;
using System.Linq;
using AegisPC.Core.Models;

namespace AegisPC.Performance.Process
{
    /// <summary>
    /// Builds a hierarchical process tree from a flat list of process telemetry.
    /// </summary>
    public static class ProcessTreeBuilder
    {
        public static List<ProcessTreeNode> BuildTree(IEnumerable<ProcessInfo> processes)
        {
            var processList = processes.ToList();
            var processMap = processList.ToDictionary(p => p.PID, p => new ProcessTreeNode
            {
                ProcessInfo = p,
                Children = new List<ProcessTreeNode>()
            });

            var rootNodes = new List<ProcessTreeNode>();

            foreach (var node in processMap.Values)
            {
                int parentPid = node.ProcessInfo.ParentPid;
                if (parentPid > 0 && processMap.TryGetValue(parentPid, out var parentNode) && parentNode != node)
                {
                    parentNode.Children.Add(node);
                }
                else
                {
                    rootNodes.Add(node);
                }
            }

            // Assign depths recursively
            AssignDepths(rootNodes, 0);

            return rootNodes;
        }

        private static void AssignDepths(IEnumerable<ProcessTreeNode> nodes, int depth)
        {
            foreach (var node in nodes)
            {
                node.Depth = depth;
                AssignDepths(node.Children, depth + 1);
            }
        }
    }
}
