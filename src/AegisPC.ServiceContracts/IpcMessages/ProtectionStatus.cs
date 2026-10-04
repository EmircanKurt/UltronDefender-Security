using System;
using System.Text.Json.Serialization;

namespace AegisPC.ServiceContracts.IpcMessages
{
    public class ProtectionStatus
    {
        /// <summary>Actual registered ransomware observer roots, not configured folder claims; null means unobserved.</summary>
        public int? RansomwareProtectedFolderCount { get; set; }
        /// <summary>Observed canary manager count; null means unobserved.</summary>
        public int? RansomwareCanaryFileCount { get; set; }
        /// <summary>Confirmed containment count only when an actual action counter is available; alerts are not containments.</summary>
        public int? RansomwareConfirmedContainments { get; set; }
        /// <summary>Observed listener health; null identifies an older service whose coverage is not verified.</summary>
        public AegisPC.Core.Models.ProtectionHealthSnapshot? Health { get; set; }
        /// <summary>Matches a solicited status to its request; empty identifies an uncorrelated legacy or event response.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public Guid RequestId { get; set; }

        public bool IsServiceRunning { get; set; }
        public bool IsRealTimeEnabled { get; set; }
        /// <summary>Observed optional local static-review configuration when the service has a wired AI plugin; null means unsupported/unobserved, not independent Guardian protection.</summary>
        public bool? IsUltronAiEnabled { get; set; }
        public bool IsNetworkProtectionEnabled { get; set; }
        public bool IsRansomwareShieldEnabled { get; set; }
        public bool IsAmsiEnabled { get; set; }
        public bool ScanScheduleEnabled { get; set; }
        public int ScheduledScanHour { get; set; } = 12;
        public int ScheduledScanIntervalHours { get; set; } = 24;
        /// <summary>Whether automatic scans may run while the interactive user is idle.</summary>
        public bool IdleScanEnabled { get; set; }
        /// <summary>Minimum uninterrupted idle duration before an automatic scan, in minutes.</summary>
        public int IdleScanThresholdMinutes { get; set; } = 10;
        /// <summary>Minimum interval between idle scans, in hours.</summary>
        public int IdleScanIntervalHours { get; set; } = 24;
        /// <summary>Whether idle scans are deferred while the device runs on battery.</summary>
        public bool SkipIdleScanOnBattery { get; set; } = true;
        public AegisPC.Core.Enums.ScanResourceMode ScanResourceMode { get; set; } = AegisPC.Core.Enums.ScanResourceMode.Auto;
        public bool EnableAutoQuarantine { get; set; } = true;
        public int AutoQuarantineThreshold { get; set; } = 85;
        public DateTime? LastThreatTime { get; set; }
        public int TotalThreatsBlocked24h { get; set; }
        public TimeSpan ServiceUptime { get; set; }
        public required string ProtectionLevel { get; set; }
    }
}
