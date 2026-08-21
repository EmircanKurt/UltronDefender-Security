using System.Collections.Generic;

namespace AegisPC.Core.Models;

public class ProcessTreeNode
{
    public ProcessInfo ProcessInfo { get; set; } = new();
    public List<ProcessTreeNode> Children { get; set; } = new();
    public int Depth { get; set; }
}
