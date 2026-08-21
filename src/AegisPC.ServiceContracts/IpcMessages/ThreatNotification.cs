using System;
using AegisPC.Core.Enums;

namespace AegisPC.ServiceContracts.IpcMessages
{
    public class ThreatNotification
    {
        public required string FilePath { get; set; }
        public required string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public required string ThreatName { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public required string ActionTaken { get; set; }
        public required string Details { get; set; }
        public DateTime DetectedAt { get; set; }
    }
}
