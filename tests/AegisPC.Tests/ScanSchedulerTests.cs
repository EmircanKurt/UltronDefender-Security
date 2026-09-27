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

        [Fact]
        public void ScanScheduler2_BatteryMode_AppliesCalmProfile()
        {
            // On battery -> Low (Calm)
            var profileOnBattery = ScanScheduleEvaluator.DetermineScheduledScanProfile(isOnBattery: true, AegisPC.Core.Enums.ScanResourceMode.Maximum);
            Assert.Equal(AegisPC.Core.Enums.ScanResourceMode.Low, profileOnBattery);

            // On AC power -> Preserves preferred mode
            var profileOnAc = ScanScheduleEvaluator.DetermineScheduledScanProfile(isOnBattery: false, AegisPC.Core.Enums.ScanResourceMode.Maximum);
            Assert.Equal(AegisPC.Core.Enums.ScanResourceMode.Maximum, profileOnAc);
        }

        [Fact]
        public void ScanScheduler2_FullscreenGame_DefersScheduledScan()
        {
            // Fullscreen active + Game mode enabled -> Should defer
            Assert.True(ScanScheduleEvaluator.ShouldDeferForFullscreenOrGame(isFullscreenActive: true, isGamingModeEnabled: true));

            // Fullscreen not active -> Do not defer
            Assert.False(ScanScheduleEvaluator.ShouldDeferForFullscreenOrGame(isFullscreenActive: false, isGamingModeEnabled: true));

            // Gaming mode disabled -> Do not defer
            Assert.False(ScanScheduleEvaluator.ShouldDeferForFullscreenOrGame(isFullscreenActive: true, isGamingModeEnabled: false));
        }

        [Fact]
        public void ScanScheduler2_HighDiskActivity_ThrottlesScan()
        {
            // Disk activity 85% (> 80%) -> Should throttle
            Assert.True(ScanScheduleEvaluator.ShouldThrottleForDiskBusy(85.0, 80.0));

            // Disk activity 40% (< 80%) -> Should not throttle
            Assert.False(ScanScheduleEvaluator.ShouldThrottleForDiskBusy(40.0, 80.0));

            // Exactly 80% -> Should throttle
            Assert.True(ScanScheduleEvaluator.ShouldThrottleForDiskBusy(80.0, 80.0));
        }
    }
}
