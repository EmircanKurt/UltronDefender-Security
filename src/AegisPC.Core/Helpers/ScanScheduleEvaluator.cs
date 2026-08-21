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
    }
}
