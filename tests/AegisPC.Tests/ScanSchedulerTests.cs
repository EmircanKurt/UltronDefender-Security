using System;
using AegisPC.Core.Helpers;
using Xunit;

namespace AegisPC.Tests
{
    public class ScanSchedulerTests
    {
        [Fact]
        public void Test_DailySchedule()
        {
            var now = new DateTime(2026, 8, 19, 14, 30, 0); // 14:30
            // Scheduled for 14, not run today -> True
            Assert.True(ScanScheduleEvaluator.IsDailyScanDue(now, 14, null));

            // Scheduled for 14, already run today -> False
            var lastRunToday = new DateTime(2026, 8, 19, 14, 0, 0);
            Assert.False(ScanScheduleEvaluator.IsDailyScanDue(now, 14, lastRunToday));

            // Scheduled for 15, current hour 14 -> False
            Assert.False(ScanScheduleEvaluator.IsDailyScanDue(now, 15, null));
        }

        [Fact]
        public void Test_WeeklySchedule()
        {
            var wednesday = new DateTime(2026, 8, 19, 14, 0, 0); // Wednesday
            Assert.Equal(DayOfWeek.Wednesday, wednesday.DayOfWeek);

            // Scheduled for Wednesday 14:00, not run -> True
            Assert.True(ScanScheduleEvaluator.IsWeeklyScanDue(wednesday, DayOfWeek.Wednesday, 14, null));

            // Scheduled for Thursday 14:00, current day Wednesday -> False
            Assert.False(ScanScheduleEvaluator.IsWeeklyScanDue(wednesday, DayOfWeek.Thursday, 14, null));
        }

        [Fact]
        public void Test_IdleDetection()
        {
            var idleThreshold = TimeSpan.FromMinutes(10);
            var minInterval = TimeSpan.FromHours(4);

            // User idle for 15 mins (threshold 10 mins), never run -> True
            Assert.True(ScanScheduleEvaluator.IsIdleScanDue(TimeSpan.FromMinutes(15), idleThreshold, null, minInterval));

            // User idle for 5 mins (below threshold) -> False
            Assert.False(ScanScheduleEvaluator.IsIdleScanDue(TimeSpan.FromMinutes(5), idleThreshold, null, minInterval));

            // User idle for 15 mins, but scan ran 10 mins ago -> False
            var recentRun = DateTime.UtcNow.AddMinutes(-10);
            Assert.False(ScanScheduleEvaluator.IsIdleScanDue(TimeSpan.FromMinutes(15), idleThreshold, recentRun, minInterval));
        }
    }
}
