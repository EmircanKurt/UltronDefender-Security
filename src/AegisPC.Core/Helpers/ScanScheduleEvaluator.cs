using System;

namespace AegisPC.Core.Helpers
{
    public static class ScanScheduleEvaluator
    {
        public static bool IsDailyScanDue(DateTime now, int scheduledHour, DateTime? lastRunDate)
        {
            if (now.Hour != scheduledHour) return false;
            if (lastRunDate.HasValue && lastRunDate.Value.Date == now.Date) return false;
            return true;
        }

        public static bool IsIntervalScanDue(DateTime now, double intervalHours, DateTime? lastRunTime)
        {
            if (intervalHours <= 0) intervalHours = 24;
            if (!lastRunTime.HasValue) return true;
            return (now - lastRunTime.Value).TotalHours >= intervalHours;
        }

        public static bool IsWeeklyScanDue(DateTime now, DayOfWeek scheduledDay, int scheduledHour, DateTime? lastRunDate)
        {
            if (now.DayOfWeek != scheduledDay) return false;
            if (now.Hour != scheduledHour) return false;
            if (lastRunDate.HasValue && (now - lastRunDate.Value).TotalDays < 6 && lastRunDate.Value.Date == now.Date) return false;
            return true;
        }

        public static bool IsIdleScanDue(TimeSpan idleDuration, TimeSpan idleThreshold, DateTime? lastRunDate, TimeSpan minIntervalBetweenIdleScans)
        {
            if (idleDuration < idleThreshold) return false;
            if (lastRunDate.HasValue && (DateTime.UtcNow - lastRunDate.Value) < minIntervalBetweenIdleScans) return false;
            return true;
        }

        /// <summary>
        /// Pil modunda otomatik Sakin (Low) profil uygular; AC gücünde ise kullanıcının tercih ettiği modu korur.
        /// </summary>
        public static Enums.ScanResourceMode DetermineScheduledScanProfile(bool isOnBattery, Enums.ScanResourceMode preferredMode)
        {
            return isOnBattery && preferredMode != Enums.ScanResourceMode.VeryLow
                ? Enums.ScanResourceMode.Low : preferredMode;
        }

        /// <summary>
        /// Kullanıcı tam ekranda oyun oynarken veya sunum yaparken planlı taramayı erteleme kararı verir.
        /// </summary>
        public static bool ShouldDeferForFullscreenOrGame(bool isFullscreenActive, bool isGamingModeEnabled = true)
        {
            return isGamingModeEnabled && isFullscreenActive;
        }

        /// <summary>
        /// Disk aktivitesi belirlenen eşiği (varsayılan %80) aştığında taramayı sınırlama veya erteleme kararı verir.
        /// </summary>
        public static bool ShouldThrottleForDiskBusy(double diskBusyPercent, double thresholdPercent = 80.0)
        {
            return diskBusyPercent >= thresholdPercent;
        }
    }
}
