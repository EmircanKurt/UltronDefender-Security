using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Contracts.ThreatIntelligence;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Scanning;
using AegisPC.Security.ThreatIntelligence;
using Xunit;

namespace AegisPC.Tests
{
    public class MultiSignalTrustAndScannerControlTests : IDisposable
    {
        private readonly string _testSandbox;

        public MultiSignalTrustAndScannerControlTests()
        {
            _testSandbox = Path.Combine(Path.GetTempPath(), "Aegis_MultiSignal_" + Guid.NewGuid().ToString("N"));
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
        public async Task ScanQueueCoordinator_PauseAndResume_PausesExecution()
        {
            var coordinator = new ScanQueueCoordinator();
            int filesProcessed = 0;
            var processedSignal = new ManualResetEventSlim(false);

            // Producer emits 10 executable/binary files
            Func<Func<string, Task>, Task> producer = async queueFunc =>
            {
                for (int i = 0; i < 10; i++)
                {
                    await queueFunc(Path.Combine(_testSandbox, $"file_{i}.bin"));
                }
            };

            // Worker function
            Func<string, CancellationToken, Task<FileScanDetailedResult>> worker = async (path, ct) =>
            {
                Interlocked.Increment(ref filesProcessed);
                processedSignal.Set();
                await Task.Delay(10, ct);
                return FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.FromMilliseconds(5));
            };

            var findings = new ConcurrentBag<SecurityFinding>();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            // Start paused
            coordinator.PauseScan();
            Assert.True(coordinator.IsPaused);

            var scanTask = coordinator.ExecuteScanQueueDetailedAsync(
                _testSandbox,
                ScanType.Custom,
                producer,
                worker,
                findings,
                (cur, tot, scn, skp, fail, tout) => { },
                cts.Token);

            // Give it time: while paused, no files should complete
            await Task.Delay(100);
            Assert.Equal(0, filesProcessed);

            // Resume
            coordinator.ResumeScan();
            Assert.False(coordinator.IsPaused);

            // Wait for completion
            var summary = await scanTask;
            Assert.True(summary.ScannedFiles > 0);
            Assert.True(filesProcessed > 0);
        }

        [Fact]
        public async Task ScanCoordinatorService_Cancellation_ReturnsCancelledScanResultAndInvokesCompleted()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var scanner = new FileScannerService(hashService, sigVerifier, new RiskScoringEngine(), allowlist, findingService);
            var coordinator = new ScanCoordinatorService(scanner, findingService);

            for (int i = 0; i < 200; i++)
            {
                File.WriteAllText(Path.Combine(_testSandbox, $"test_{i}.bin"), "sample data");
            }

            ScanResult? completedResult = null;
            coordinator.ScanCompleted += res =>
            {
                completedResult = res;
            };

            coordinator.ProgressChanged += _ => coordinator.CancelScan();

            var scanTask = coordinator.StartScanAsync(ScanType.Custom, _testSandbox);

            await Task.Delay(20);
            coordinator.CancelScan();

            var finalResult = await scanTask;

            Assert.NotNull(finalResult);
            Assert.Equal(ScanStatus.Cancelled, finalResult.Status);
            Assert.NotNull(completedResult);
            Assert.Equal(ScanStatus.Cancelled, completedResult.Status);
            Assert.False(coordinator.IsScanning);
        }

        [Fact]
        public void ThreatIntelligenceStore_OfflineLookup_MaliciousAndTrustedHashes()
        {
            var store = new ThreatIntelligenceStore();

            // Check known EICAR hash
            const string eicarSha256 = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";
            bool isMalicious = store.IsMaliciousHash(eicarSha256, out var record);

            Assert.True(isMalicious);
            Assert.NotNull(record);
            Assert.Equal("EICAR-Standard-AV-Test-File", record.ThreatName);
            Assert.Equal(100, record.Severity);

            // Register and check trusted hash
            const string trustedSha256 = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555FFFF66660000111122223333";
            store.RegisterTrustedHash(trustedSha256);
            Assert.True(store.IsTrustedHash(trustedSha256));

            // Publisher verification
            Assert.True(store.IsTrustedPublisher("Microsoft Corporation"));
            Assert.True(store.IsTrustedPublisher("Valve Corporation"));
            Assert.False(store.IsTrustedPublisher("Unknown Hacker Group"));
        }

        [Fact]
        public async Task MultiSignal_MaliciousHash_OverridesValidSignature()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var intel = new ThreatIntelligenceStore();

            // Register test malicious hash
            const string testBadHash = "1111222233334444555566667777888899990000AAAABBBBCCCCDDDDEEEEFFFF";
            intel.RegisterMaliciousHash(testBadHash, "Trojan.SignedBypass.Test", "Trojan", 100);

            var hub = DetectionHubFactory.CreateDefault(
                hashService: hashService,
                signatureVerifier: sigVerifier,
                threatStore: intel);

            var context = new DetectionContext
            {
                FilePath = Path.Combine(_testSandbox, "signed_trojan.exe"),
                SHA256 = testBadHash
            };
            File.WriteAllText(context.FilePath, "dummy binary payload");

            var result = await hub.EvaluateAsync(context);

            // Malicious hash must override and result in ConfirmedMalicious regardless of any other factors
            Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
            Assert.Equal(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
            Assert.Contains("Trojan.SignedBypass.Test", result.ThreatTitle);
        }

        [Fact]
        public async Task MultiSignal_SystemProcessMasquerading_FlagsHighRiskAntiEvasion()
        {
            var sigVerifier = new SignatureVerifier();
            var detector = new LocationReputationDetector(sigVerifier);

            string fakeSvchost = Path.Combine(_testSandbox, "svchost.exe");
            File.WriteAllText(fakeSvchost, "fake binary content");

            var context = new DetectionContext
            {
                FilePath = fakeSvchost,
                SHA256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            };

            var evidences = (await detector.EvaluateAsync(context)).ToList();

            // svchost outside C:\Windows\System32 must be flagged as SystemProcessMasquerading
            var masquerading = evidences.FirstOrDefault(e => e.RuleName == "Evasion.SystemProcessMasquerading");
            Assert.NotNull(masquerading);
            Assert.Equal(EvidenceCategory.AntiEvasion, masquerading.Category);
            Assert.True(masquerading.ScoreContribution >= 70);
        }

        [Fact]
        public async Task MultiSignal_UnsignedDownloadsBinary_DoesNotFalselyFlagPup()
        {
            var sigVerifier = new SignatureVerifier();
            var detector = new LocationReputationDetector(sigVerifier);

            // Simulate user downloads directory
            string userDownloads = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string testDownloadFile = Path.Combine(userDownloads, "Downloads", "my_clean_open_source_tool.exe");

            // We test the rule matching directly on the detector
            var context = new DetectionContext
            {
                FilePath = testDownloadFile,
                SHA256 = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
            };

            var evidences = (await detector.EvaluateAsync(context)).ToList();

            // It should NOT be flagged as PUP just because it's an unsigned file in Downloads
            var pupEvidence = evidences.FirstOrDefault(e => e.RuleName.Contains("PUP", StringComparison.OrdinalIgnoreCase));
            Assert.Null(pupEvidence);
        }

        [Fact]
        public void ScanViewModel_PauseAndCancel_TransitionsUIStateCleanly()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var scanner = new FileScannerService(hashService, sigVerifier, new RiskScoringEngine(), allowlist, findingService);
            var coordinator = new ScanCoordinatorService(scanner, findingService);

            var vm = new AegisPC.App.ViewModels.ScanViewModel(coordinator, findingService);

            // Simulate running scan
            vm.ResetScanState(ScanType.Quick);
            Assert.True(vm.IsScanning);
            Assert.False(vm.IsScanFinishedView);
            Assert.False(vm.IsPaused);
            Assert.Equal("Duraklat", vm.PauseButtonText);

            // Toggle Pause
            vm.TogglePauseResume();
            Assert.True(vm.IsPaused);
            Assert.Equal("Devam Et", vm.PauseButtonText);

            // Toggle Resume
            vm.TogglePauseResume();
            Assert.False(vm.IsPaused);
            Assert.Equal("Duraklat", vm.PauseButtonText);

            // Cancel Scan
            vm.CancelScan();
            Assert.False(vm.IsScanning);
            Assert.True(vm.IsNotScanning);
            Assert.False(vm.IsPaused);
            Assert.True(vm.IsScanFinishedView);
            Assert.True(vm.IsCancellationRequested);
            Assert.Equal("Tehdit Taraması İptal Edildi", vm.ScanResultTitle);
            Assert.Equal("Tarama İptal Edildi", vm.CleanStateTitle);
            Assert.Contains("kullanıcı tarafından durduruldu", vm.ScanStatusText);
        }
    }
}
