using System;
using AegisPC.Core.Enums;

namespace AegisPC.Infrastructure.Configuration
{
    /// <summary>
    /// Application settings POCO class.
    /// </summary>
    public class AppSettings
    {
        public ThemeMode Theme { get; set; } = ThemeMode.System;
        public string Language { get; set; } = "tr-TR";
        public bool IsRealTimeMonitoringEnabled { get; set; } = true;
        /// <summary>Enables optional local static Ultron AI review; disabling it does not disable signatures, AMSI, or mandatory action validation.</summary>
        public bool IsUltronAiEnabled { get; set; } = true;
        public bool NotificationsEnabled { get; set; } = true;
        public bool ScanScheduleEnabled { get; set; } = false;
        public string ScanScheduleCron { get; set; } = "0 0 * * *"; // Daily at midnight
        public int DataRetentionDays { get; set; } = 30;
        public bool IsCloudReputationEnabled { get; set; } = false;
        public bool IsAiExplanationsEnabled { get; set; } = false;
        public byte[]? ReputationApiKeyEncrypted { get; set; }
        public int PerformanceSampleIntervalMs { get; set; } = 2000;
        public bool IsFirstRun { get; set; } = true;
        public bool OnboardingCompleted { get; set; } = false;
        public DateTime? LastHealthCheck { get; set; }
        public bool IsFileProtectionEnabled { get; set; } = true;
        public bool IsRansomwareShieldEnabled { get; set; } = true;
        public bool IsNetworkProtectionEnabled { get; set; } = false;
        public bool EnableAutoQuarantine { get; set; } = true;
        public int AutoQuarantineThreshold { get; set; } = 85;
        public bool IsProcessMonitoringEnabled { get; set; } = true;
        public int ScheduledScanHour { get; set; } = 12;
        public string ScheduledScanDay { get; set; } = "Her Gün";
        public int ScheduledScanIntervalHours { get; set; } = 24;
        public ScanResourceMode ScanResourceMode { get; set; } = ScanResourceMode.Auto;
        /// <summary>
        /// Stores the last confirmed manual scan profile independently from the scheduled scan profile;
        /// null means no manual preference has been saved.
        /// </summary>
        public ScanResourceMode? LastManualScanResourceMode { get; set; }
        /// <summary>Enables resource-aware maintenance while interactive users are idle.</summary>
        public bool IdleScanEnabled { get; set; } = true;
        /// <summary>Minimum interactive-session idle time before a background scan may start.</summary>
        public int IdleScanThresholdMinutes { get; set; } = 10;
        /// <summary>Minimum hours between successfully completed idle scans.</summary>
        public int IdleScanIntervalHours { get; set; } = 24;
        /// <summary>Defers idle maintenance while the system is on battery.</summary>
        public bool SkipIdleScanOnBattery { get; set; } = true;
        public bool RememberScanResourceMode { get; set; } = false;
        public string? MalwareBazaarApiKey { get; set; }
        public DateTime? LastThreatFeedUpdateUtc { get; set; }
        public bool EnableWscRegistration { get; set; } = false; // Ürün henüz birincil AV olarak konumlanamaz
        public System.Collections.Generic.List<string> DismissedIncidentIds { get; set; } = new();
    }
}
