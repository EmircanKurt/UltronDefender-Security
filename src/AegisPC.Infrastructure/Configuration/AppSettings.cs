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
        public bool NotificationsEnabled { get; set; } = true;
        public bool ScanScheduleEnabled { get; set; } = false;
        public string ScanScheduleCron { get; set; } = "0 0 * * *"; // Daily at midnight
        public int DataRetentionDays { get; set; } = 30;
        public bool IsCloudReputationEnabled { get; set; } = false;
        public bool IsAiExplanationsEnabled { get; set; } = false;
        public byte[]? ReputationApiKeyEncrypted { get; set; }
        public int PerformanceSampleIntervalMs { get; set; } = 2000;
        public int MaxScanConcurrency { get; set; } = Environment.ProcessorCount;
        public bool IsFirstRun { get; set; } = true;
        public bool OnboardingCompleted { get; set; } = false;
        public DateTime? LastHealthCheck { get; set; }
        public bool IsFileProtectionEnabled { get; set; } = true;
        public bool IsRansomwareShieldEnabled { get; set; } = true;
        public bool IsProcessMonitoringEnabled { get; set; } = true;
        public int ScheduledScanHour { get; set; } = 12;
        public string ScheduledScanDay { get; set; } = "Her Gün";
    }
}
