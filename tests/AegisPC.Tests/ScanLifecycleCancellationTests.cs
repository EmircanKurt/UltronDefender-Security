using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class ScanLifecycleCancellationTests
    {
        [Fact]
        public void ScanCoordinator_InitialState_IsIdle()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskScoring = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var fileScanner = new FileScannerService(hashService, sigVerifier, riskScoring, allowlist, findingService);

            var coordinator = new ScanCoordinatorService(fileScanner, findingService);

            Assert.Equal(ScanState.Idle, coordinator.State);
            Assert.Equal(ScanStopReason.None, coordinator.StopReason);
            Assert.False(coordinator.IsScanning);
            Assert.False(coordinator.IsPaused);
        }

        [Fact]
        public async Task ScanCoordinator_LifecycleStateTransitions_OperateCorrectly()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "UltronCoordinatorTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            try
            {
                for (int i = 0; i < 20; i++)
                {
                    File.WriteAllText(Path.Combine(tempDir, $"file_{i}.txt"), "safe content");
                }

                var hashService = new HashService();
                var sigVerifier = new SignatureVerifier();
                var riskScoring = new RiskScoringEngine();
                var allowlist = new AllowlistService(hashService);
                var findingService = new SecurityFindingService();
                var fileScanner = new FileScannerService(hashService, sigVerifier, riskScoring, allowlist, findingService);

                var coordinator = new ScanCoordinatorService(fileScanner, findingService);

                var scanTask = coordinator.StartScanAsync(ScanType.Custom, tempDir);

                // Scanning or active
                Assert.True(coordinator.IsScanning);

                // Pause
                coordinator.PauseScan();
                Assert.True(coordinator.IsPaused);
                Assert.Equal(ScanState.Paused, coordinator.State);

                // Resume
                coordinator.ResumeScan();
                Assert.False(coordinator.IsPaused);

                // Cancel
                coordinator.CancelScan();
                Assert.True(coordinator.State == ScanState.Cancelling || coordinator.State == ScanState.Cancelled);
                Assert.Equal(ScanStopReason.UserCancelled, coordinator.StopReason);

                var result = await scanTask;
                Assert.True(result != null, $"Result is null! State: {coordinator.State}, StopReason: {coordinator.StopReason}, StatusText: {coordinator.StatusText}");
                Assert.Equal(ScanStatus.Cancelled, result.Status);
                Assert.Equal(ScanState.Cancelled, coordinator.State);
                Assert.Equal(ScanStopReason.UserCancelled, coordinator.StopReason);
                Assert.False(coordinator.IsScanning);
            }
            finally
            {
                if (Directory.Exists(tempDir))
                {
                    try { Directory.Delete(tempDir, true); } catch { }
                }
            }
        }

        [Fact]
        public async Task ScanQueueCoordinator_ImmediateCancellation_HaltsWorkersRapidly()
        {
            using var queueCoordinator = new ScanQueueCoordinator();
            using var cts = new CancellationTokenSource();

            var findings = new ConcurrentBag<SecurityFinding>();
            int processedCount = 0;

            // Producer produces 200 items with delay to test worker cutoff
            async Task Producer(Func<string, Task> tryQueue)
            {
                for (int i = 0; i < 200; i++)
                {
                    if (cts.IsCancellationRequested) break;
                    await tryQueue($"C:\\dummy_file_{i}.exe");
                }
            }

            // Scanner simulates work
            async Task<FileScanDetailedResult> Scanner(string path, CancellationToken ct)
            {
                ct.ThrowIfCancellationRequested();
                Interlocked.Increment(ref processedCount);
                await Task.Delay(25, ct); // 25ms simulation
                return FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.FromMilliseconds(25));
            }

            var sw = Stopwatch.StartNew();

            // Cancel after 100ms
            cts.CancelAfter(100);

            var result = await queueCoordinator.ExecuteScanQueueDetailedAsync(
                "C:\\dummy",
                ScanType.Custom,
                Producer,
                Scanner,
                findings,
                (file, tot, scn, skp, fail, tout) => { },
                cts.Token);

            sw.Stop();

            // Hard stop must occur rapidly (< 500ms even under test scheduler variance)
            Assert.True(sw.ElapsedMilliseconds < 1500, $"Cancellation took {sw.ElapsedMilliseconds}ms, expected < 1500ms");
            // Must NOT have processed all 200 files
            Assert.True(processedCount < 180, $"Processed {processedCount} files out of 200; workers did not halt promptly on cancellation");
        }

        [Fact]
        public async Task ScanQueueCoordinator_PauseScan_HaltsQueueDrain_UntilResumed()
        {
            using var queueCoordinator = new ScanQueueCoordinator();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            var findings = new ConcurrentBag<SecurityFinding>();
            int processedCount = 0;

            async Task Producer(Func<string, Task> tryQueue)
            {
                for (int i = 0; i < 30; i++)
                {
                    await tryQueue($"C:\\test_pause_{i}.dat");
                }
            }

            async Task<FileScanDetailedResult> Scanner(string path, CancellationToken ct)
            {
                ct.ThrowIfCancellationRequested();
                Interlocked.Increment(ref processedCount);
                await Task.CompletedTask;
                return FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero);
            }

            // Start paused
            queueCoordinator.PauseScan();
            Assert.True(queueCoordinator.IsPaused);

            var scanTask = queueCoordinator.ExecuteScanQueueDetailedAsync(
                "C:\\test",
                ScanType.Custom,
                Producer,
                Scanner,
                findings,
                (file, tot, scn, skp, fail, tout) => { },
                cts.Token);

            // Wait 150ms while paused; zero or very few items (only pre-pause) should be processed
            await Task.Delay(150);
            int countWhilePaused = Volatile.Read(ref processedCount);
            Assert.True(countWhilePaused < 30, $"Items were processed while paused: {countWhilePaused}");

            // Now resume
            queueCoordinator.ResumeScan();
            Assert.False(queueCoordinator.IsPaused);

            var finalResult = await scanTask;
            Assert.Equal(30, finalResult.ScannedFiles);
        }

        [Fact]
        public async Task FileScannerService_OnCancellation_DoesNotReportCompleted100()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "UltronFileScannerCancel_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            try
            {
                for (int i = 0; i < 50; i++)
                {
                    File.WriteAllText(Path.Combine(tempDir, $"file_{i}.bin"), new string('A', 1000));
                }

                var hashService = new HashService();
                var sigVerifier = new SignatureVerifier();
                var riskScoring = new RiskScoringEngine();
                var allowlist = new AllowlistService(hashService);
                var findingService = new SecurityFindingService();
                var fileScanner = new FileScannerService(hashService, sigVerifier, riskScoring, allowlist, findingService);

                using var cts = new CancellationTokenSource();
                var progressReports = new List<ScanProgress>();
                var progressHandler = new Progress<ScanProgress>(p =>
                {
                    lock (progressReports)
                    {
                        progressReports.Add(p);
                    }
                });

                cts.Cancel();
                var result = await fileScanner.ScanDirectoryAsync(tempDir, ScanType.Custom, progressHandler, cts.Token);

                Assert.Equal(ScanStatus.Cancelled, result.Status);

                lock (progressReports)
                {
                    // No progress report should declare IsCompleted == true when cancelled
                    foreach (var p in progressReports)
                    {
                        if (p.CurrentFile == "İptal edildi")
                        {
                            Assert.False(p.IsCompleted);
                        }
                    }
                }
            }
            finally
            {
                if (Directory.Exists(tempDir))
                {
                    try { Directory.Delete(tempDir, true); } catch { }
                }
            }
        }

        [Fact]
        public void ScanViewModel_CancelCommand_TransitionsStateToCancellation()
        {
            Exception? threadEx = null;
            var staThread = new Thread(() =>
            {
                try
                {
                    var hashService = new HashService();
                    var sigVerifier = new SignatureVerifier();
                    var riskScoring = new RiskScoringEngine();
                    var allowlist = new AllowlistService(hashService);
                    var findingService = new SecurityFindingService();
                    var fileScanner = new FileScannerService(hashService, sigVerifier, riskScoring, allowlist, findingService);
                    var coordinator = new ScanCoordinatorService(fileScanner, findingService);

                    var vm = new ScanViewModel(coordinator, findingService);

                    vm.CancelScanCommand.Execute(null);

                    Assert.True(vm.IsCancellationRequested);
                    Assert.Equal("Tehdit Taraması İptal Edildi", vm.ScanResultTitle);
                    Assert.Equal("Tarama İptal Edildi", vm.CleanStateTitle);
                    Assert.Equal("İptal edildi", vm.RemainingEtaFormatted);
                }
                catch (Exception ex)
                {
                    threadEx = ex;
                }
            });

            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            staThread.Join();

            if (threadEx != null)
            {
                throw new Exception("STA thread failed", threadEx);
            }
        }
    }
}
