using System;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class ScanDurationSynchronizationTests
    {
        [Fact]
        public void FormatDuration_HandlesZeroAndNegativeTimeSpans()
        {
            Assert.Equal("0 dk 00 sn", ScanViewModel.FormatDuration(TimeSpan.Zero));
            Assert.Equal("0 dk 00 sn", ScanViewModel.FormatDuration(TimeSpan.FromSeconds(-10)));
        }

        [Fact]
        public void FormatDuration_FormatsSecondsCorrectly()
        {
            Assert.Equal("0 dk 15 sn", ScanViewModel.FormatDuration(TimeSpan.FromSeconds(15)));
            Assert.Equal("0 dk 59 sn", ScanViewModel.FormatDuration(TimeSpan.FromSeconds(59)));
        }

        [Fact]
        public void FormatDuration_FormatsMinutesAndSecondsCorrectly()
        {
            Assert.Equal("1 dk 00 sn", ScanViewModel.FormatDuration(TimeSpan.FromMinutes(1)));
            Assert.Equal("2 dk 05 sn", ScanViewModel.FormatDuration(TimeSpan.FromSeconds(125)));
            Assert.Equal("14 dk 42 sn", ScanViewModel.FormatDuration(TimeSpan.FromSeconds(882)));
        }

        [Fact]
        public void FormatDuration_FormatsHoursMinutesSecondsCorrectly()
        {
            var duration = new TimeSpan(1, 23, 45);
            Assert.Equal("1 sa 23 dk 45 sn", ScanViewModel.FormatDuration(duration));

            var multiHour = new TimeSpan(2, 5, 9);
            Assert.Equal("2 sa 05 dk 09 sn", ScanViewModel.FormatDuration(multiHour));
        }

        [Fact]
        public void ScanCoordinator_TracksAuthoritativeElapsedTime()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskScoring = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var fileScanner = new FileScannerService(hashService, sigVerifier, riskScoring, allowlist, findingService);

            IScanCoordinatorService coordinator = new ScanCoordinatorService(fileScanner, findingService);

            Assert.Equal(TimeSpan.Zero, coordinator.ElapsedTime);

            // Simulate progress registration
            coordinator.RegisterExternalScanProgress(new ScanProgress
            {
                ScanType = ScanType.Quick,
                ScannedFiles = 50,
                TotalFiles = 100,
                ElapsedTime = TimeSpan.FromSeconds(12),
                ProgressPercent = 50
            });

            Assert.Equal(TimeSpan.FromSeconds(12), coordinator.ElapsedTime);

            // Simulate completed external scan
            coordinator.CompleteExternalScan(new ScanResult
            {
                ScanType = ScanType.Quick,
                ScannedFiles = 100,
                TotalFiles = 100,
                ElapsedMs = 24500,
                Status = ScanStatus.Completed
            });

            Assert.Equal(TimeSpan.FromMilliseconds(24500), coordinator.ElapsedTime);
        }
    }
}
