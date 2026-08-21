using System;

namespace AegisPC.Core.Models
{
    public class BehaviorAlert
    {
        public required string RuleName { get; set; }
        public required string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public double Confidence { get; set; }
        public required string Details { get; set; }
        public DateTime DetectedAt { get; set; }
        public string? ActionTaken { get; set; }
    }
}
