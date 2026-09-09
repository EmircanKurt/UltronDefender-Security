using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class ScanSessionAndWindowLifecycleTests : IDisposable
    {
        private readonly string _testSandbox;

        public ScanSessionAndWindowLifecycleTests()
        {
            _testSandbox = Path.Combine(Path.GetTempPath(), "Aegis_SessionTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testSandbox);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testSandbox))
                {
                    Directory.Delete(_testSandbox, true);
                }
            }
            catch { }
        }

        [Fact]
        public void ScanSessionManager_GetOrCreateSession_ReturnsSameActiveSession()
        {
            var manager = new ScanSessionManager();

            var session1 = manager.GetOrCreateSession(ScanType.Quick, string.Empty, out bool isNew1);
            Assert.True(isNew1);
            Assert.NotNull(session1);
            Assert.True(session1.IsActive);

            var session2 = manager.GetOrCreateSession(ScanType.Quick, string.Empty, out bool isNew2);
            Assert.False(isNew2);
            Assert.Same(session1, session2);
            Assert.Equal(session1.SessionId, session2.SessionId);
        }

        [Fact]
        public void ScanSessionManager_AfterMarkEnded_CreatesNewSession()
        {
            var manager = new ScanSessionManager();

            var session1 = (ScanSession)manager.GetOrCreateSession(ScanType.Quick, string.Empty, out bool isNew1);
            Assert.True(isNew1);

            session1.MarkEnded();
            Assert.False(session1.IsActive);

            var session2 = manager.GetOrCreateSession(ScanType.Full, string.Empty, out bool isNew2);
            Assert.True(isNew2);
            Assert.NotEqual(session1.SessionId, session2.SessionId);
            Assert.Equal(ScanType.Full, session2.ScanType);
        }

        [Fact]
        public async Task ScanCoordinatorService_FiresScanSessionStartedEvent()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var scanner = new FileScannerService(hashService, sigVerifier, new RiskScoringEngine(), allowlist, findingService);
            var coordinator = new ScanCoordinatorService(scanner, findingService);

            IScanSession? startedSession = null;
            coordinator.ScanSessionStarted += session =>
            {
                startedSession = session;
            };

            for (int i = 0; i < 3; i++)
            {
                File.WriteAllText(Path.Combine(_testSandbox, $"file_{i}.txt"), "sample benign content");
            }

            var resultTask = coordinator.StartScanAsync(ScanType.Custom, _testSandbox);
            Assert.NotNull(startedSession);
            Assert.True(startedSession.IsActive);
            Assert.Equal(ScanType.Custom, startedSession.ScanType);

            var result = await resultTask;
            Assert.NotNull(result);
            Assert.False(startedSession.IsActive);
        }

        [Fact]
        public async Task ScanCoordinatorService_DuplicateStartScan_ReturnsRunningTaskWithoutNewScan()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var scanner = new FileScannerService(hashService, sigVerifier, new RiskScoringEngine(), allowlist, findingService);
            var coordinator = new ScanCoordinatorService(scanner, findingService);

            for (int i = 0; i < 5; i++)
            {
                File.WriteAllText(Path.Combine(_testSandbox, $"doc_{i}.dat"), "data");
            }

            int sessionStartedCount = 0;
            coordinator.ScanSessionStarted += _ => Interlocked.Increment(ref sessionStartedCount);

            var task1 = coordinator.StartScanAsync(ScanType.Custom, _testSandbox);
            var task2 = coordinator.StartScanAsync(ScanType.Custom, _testSandbox);

            Assert.Same(task1, task2);
            var res1 = await task1;
            var res2 = await task2;

            Assert.Same(res1, res2);
            Assert.Equal(2, sessionStartedCount);
        }

        [Fact]
        public void ScanSession_ForwardActions_TriggersDelegates()
        {
            bool paused = false;
            bool resumed = false;
            bool cancelled = false;

            using var cts = new CancellationTokenSource();
            var session = new ScanSession(
                ScanType.Quick,
                string.Empty,
                cts,
                onPause: () => paused = true,
                onResume: () => resumed = true,
                onCancel: () => cancelled = true);

            session.Pause();
            Assert.True(paused);

            session.Resume();
            Assert.True(resumed);

            session.Cancel();
            Assert.True(cancelled);
            Assert.True(session.CancellationToken.IsCancellationRequested);
        }
    }
}
