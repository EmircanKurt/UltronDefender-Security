using System;
using System.Collections.Generic;

namespace AegisPC.Core.Models
{
    public class RansomwareEvent
    {
        public required string AttackingProcessName { get; set; }
        public int AttackingProcessId { get; set; }
        public required string AttackingProcessPath { get; set; }
        public List<string> AffectedFiles { get; set; } = new();
        public required string ActionTaken { get; set; }
        public DateTime DetectedAt { get; set; }
    }
}
