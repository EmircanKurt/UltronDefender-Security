using System;
using System.Text.Json.Serialization;

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

        /// <summary>Optional nonzero request identity echoed by the service for a fresh status reply.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public Guid RequestId { get; set; }
    }
}
