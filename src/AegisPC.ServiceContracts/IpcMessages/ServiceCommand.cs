using System;

namespace AegisPC.ServiceContracts.IpcMessages
{
    public enum ServiceCommandType
    {
        StartScan, StopScan, EnableProtection, DisableProtection, GetStatus, UpdateSettings, 
        EnableRansomwareShield, DisableRansomwareShield, EnableNetworkProtection, DisableNetworkProtection
    }

    public class ServiceCommand
    {
        public ServiceCommandType CommandType { get; set; }
        public string? Payload { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
