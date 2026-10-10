using System;
using System.Text.Json.Serialization;

namespace AegisPC.ServiceContracts.IpcMessages
{
    public enum ServiceCommandType
    {
        StartScan, StopScan, EnableProtection, DisableProtection, GetStatus, UpdateSettings, 
        EnableRansomwareShield, DisableRansomwareShield, EnableNetworkProtection, DisableNetworkProtection,
        GetQuarantine, GetQuarantineItem, QuarantineFile, RestoreQuarantine, DeleteQuarantine, GetDeviceInventory,
        /// <summary>Enables optional local static review; requires an authenticated administrator.</summary>
        EnableUltronAi,
        /// <summary>Disables optional local static review without disabling mandatory security validation; requires an authenticated administrator.</summary>
        DisableUltronAi,
        /// <summary>Administrator-only timed file-shield pause; other layers remain unchanged.</summary>
        PauseFileProtection
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
