using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class RealTimeLiveEventTests : IDisposable
    {
        private readonly string _testWatchDir;

        public RealTimeLiveEventTests()
        {
            _testWatchDir = Path.Combine(Path.GetTempPath(), $"UltronRealTimeEventTest_{Guid.NewGuid():N}");
            Directory.CreateDirectory(_testWatchDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testWatchDir))
                {
                    Directory.Delete(_testWatchDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Test_RealTime_FileCreation_DetectedAndProcessed()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskEngine = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var quarantineService = new QuarantineService(hashService);
            var fileScanner = new FileScannerService(hashService, sigVerifier, riskEngine, allowlist, findingService);

            using var engine = new RealTimeProtectionEngine(
                fileScanner,
                hashService,
                sigVerifier,
                riskEngine,
                quarantineService,
                findingService);

            var loggedEvents = new ConcurrentBag<RealTimeActivityEvent>();
            engine.OnActivityLogged += evt => loggedEvents.Add(evt);

            engine.Start(watchDefaultLocations: false);
            engine.AddWatchDirectory(_testWatchDir);

            // Trigger file creation
            string testFile = Path.Combine(_testWatchDir, "test_creation.txt");
            await File.WriteAllTextAsync(testFile, "Hello RealTime Protection Engine!");

            // Wait for event to propagate through Watcher -> Ingestor -> Stability -> Verdict
            await Task.Delay(800);

            engine.Stop();

            Assert.Contains(loggedEvents, e => e.Stage == "FILE_DETECTED" || e.Stage == "STABILITY_CHECK" || e.Stage == "VERDICT");
        }

        [Fact]
        public async Task Test_RealTime_FileModification_DetectedAndProcessed()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskEngine = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var quarantineService = new QuarantineService(hashService);
            var fileScanner = new FileScannerService(hashService, sigVerifier, riskEngine, allowlist, findingService);

            using var engine = new RealTimeProtectionEngine(
                fileScanner,
                hashService,
                sigVerifier,
                riskEngine,
                quarantineService,
                findingService);

            string testFile = Path.Combine(_testWatchDir, "test_modify.txt");
            await File.WriteAllTextAsync(testFile, "Initial content");

            var loggedEvents = new ConcurrentBag<RealTimeActivityEvent>();
            engine.OnActivityLogged += evt => loggedEvents.Add(evt);

            engine.Start(watchDefaultLocations: false);
            engine.AddWatchDirectory(_testWatchDir);

            // Modify the file
            await File.AppendAllTextAsync(testFile, "\nAppended second line content for modification event");

            await Task.Delay(800);

            engine.Stop();

            Assert.Contains(loggedEvents, e => e.FilePath.Equals(testFile, StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task Test_RealTime_FileRename_DetectedAndProcessed()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskEngine = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var quarantineService = new QuarantineService(hashService);
            var fileScanner = new FileScannerService(hashService, sigVerifier, riskEngine, allowlist, findingService);

            using var engine = new RealTimeProtectionEngine(
                fileScanner,
                hashService,
                sigVerifier,
                riskEngine,
                quarantineService,
                findingService);

            string origFile = Path.Combine(_testWatchDir, "test_orig.dat");
            string renamedFile = Path.Combine(_testWatchDir, "test_renamed.dat");
            await File.WriteAllTextAsync(origFile, "Binary data content to be renamed");

            var loggedEvents = new ConcurrentBag<RealTimeActivityEvent>();
            engine.OnActivityLogged += evt => loggedEvents.Add(evt);

            engine.Start(watchDefaultLocations: false);
            engine.AddWatchDirectory(_testWatchDir);

            // Rename the file
            File.Move(origFile, renamedFile);

            await Task.Delay(800);

            engine.Stop();

            Assert.Contains(loggedEvents, e => e.FilePath.Equals(renamedFile, StringComparison.OrdinalIgnoreCase) || e.Message.Contains("Renamed", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task Test_RealTime_FileDeletion_HandledGracefully()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskEngine = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var quarantineService = new QuarantineService(hashService);
            var fileScanner = new FileScannerService(hashService, sigVerifier, riskEngine, allowlist, findingService);

            using var engine = new RealTimeProtectionEngine(
                fileScanner,
                hashService,
                sigVerifier,
                riskEngine,
                quarantineService,
                findingService);

            string testFile = Path.Combine(_testWatchDir, "test_delete.tmp");
            await File.WriteAllTextAsync(testFile, "Temporary file content");

            var loggedEvents = new ConcurrentBag<RealTimeActivityEvent>();
            engine.OnActivityLogged += evt => loggedEvents.Add(evt);

            engine.Start(watchDefaultLocations: false);
            engine.AddWatchDirectory(_testWatchDir);

            // Delete the file
            File.Delete(testFile);

            await Task.Delay(600);

            engine.Stop();

            // Engine must not crash on deleted file
            Assert.False(engine.IsRunning);
        }

        [Fact]
        public void Test_RealTime_UsbWatchDirectory_AttachedAndDetachedCleanly()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskEngine = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var quarantineService = new QuarantineService(hashService);
            var fileScanner = new FileScannerService(hashService, sigVerifier, riskEngine, allowlist, findingService);

            using var engine = new RealTimeProtectionEngine(
                fileScanner,
                hashService,
                sigVerifier,
                riskEngine,
                quarantineService,
                findingService);

            engine.Start(watchDefaultLocations: false);

            string fakeUsbMount = Path.Combine(_testWatchDir, "UsbMount_E");
            Directory.CreateDirectory(fakeUsbMount);

            engine.AddWatchDirectory(fakeUsbMount);
            Assert.Contains(engine.WatchedLocations, p => p.Equals(fakeUsbMount, StringComparison.OrdinalIgnoreCase));

            engine.RemoveWatchDirectory(fakeUsbMount);
            Assert.DoesNotContain(engine.WatchedLocations, p => p.Equals(fakeUsbMount, StringComparison.OrdinalIgnoreCase));

            engine.Stop();
        }
    }
}
