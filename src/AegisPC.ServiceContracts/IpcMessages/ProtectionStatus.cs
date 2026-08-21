using System;

namespace AegisPC.ServiceContracts.IpcMessages
{
    public class ProtectionStatus
    {
        public bool IsServiceRunning { get; set; }
        public bool IsRealTimeEnabled { get; set; }
        public bool IsNetworkProtectionEnabled { get; set; }
        public bool IsRansomwareShieldEnabled { get; set; }
        public bool IsAmsiEnabled { get; set; }
        public DateTime? LastThreatTime { get; set; }
        public int TotalThreatsBlocked24h { get; set; }
        public TimeSpan ServiceUptime { get; set; }
        public required string ProtectionLevel { get; set; }
    }
}
