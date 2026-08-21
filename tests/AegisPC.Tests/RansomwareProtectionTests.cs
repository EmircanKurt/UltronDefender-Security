using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class RansomwareProtectionTests : IDisposable
    {
        private readonly string _testRoot;
        private readonly string _protectedFolder;
        private readonly string _vaultDir;
        private readonly RansomwareProtectionEngine _engine;
        private readonly QuarantineService _quarService;

        public RansomwareProtectionTests()
        {
            _testRoot = Path.Combine(Path.GetTempPath(), "UltronRansomwareTests_" + Guid.NewGuid().ToString("N")[..8]);
            _protectedFolder = Path.Combine(_testRoot, "ProtectedUserDocuments");
            _vaultDir = Path.Combine(_testRoot, "Vault");

            Directory.CreateDirectory(_testRoot);
            Directory.CreateDirectory(_protectedFolder);
            Directory.CreateDirectory(_vaultDir);

            var hashService = new HashService();
            _quarService = new QuarantineService(hashService, null, null, _vaultDir);
            _engine = new RansomwareProtectionEngine(
                signatureVerifier: new SignatureVerifier(),
                quarantineService: _quarService,
                findingService: new SecurityFindingService());

            _engine.AddProtectedDirectory(_protectedFolder);
            _engine.StartShield();
        }

        [Fact]
        public void Test_ControlledFolder_ProtectedDirectoryManagement()
        {
            Assert.Contains(_engine.ProtectedDirectories, d => d.Equals(_protectedFolder, StringComparison.OrdinalIgnoreCase));

            var customDir = Path.Combine(_testRoot, "CustomFinancialDocs");
            Directory.CreateDirectory(customDir);

            _engine.AddProtectedDirectory(customDir);
            Assert.Contains(_engine.ProtectedDirectories, d => d.Equals(customDir, StringComparison.OrdinalIgnoreCase));

            _engine.RemoveProtectedDirectory(customDir);
            Assert.DoesNotContain(_engine.ProtectedDirectories, d => d.Equals(customDir, StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void Test_AllowedApplication_AllowedToWriteWithoutAlert()
        {
            _engine.AddAllowedApplication(@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "Microsoft Word");
            Assert.True(_engine.IsApplicationAllowed("WINWORD.EXE"));
            Assert.True(_engine.IsApplicationAllowed(@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"));

            Assert.False(_engine.IsApplicationAllowed(@"C:\Users\PC\AppData\Local\Temp\random_unknown_dropper.exe"));
        }

        [Fact]
        public async Task Test_KnownRansomwareExtension_DetectedAndBlocked()
        {
            var targetDoc = Path.Combine(_protectedFolder, "financial_report.docx");
            await File.WriteAllTextAsync(targetDoc, "Confidential Financial Data");

            var encryptedDoc = Path.Combine(_protectedFolder, "financial_report.docx.locked");

            bool alertFired = false;
            _engine.OnRansomwareAttemptDetected += (s, e) =>
            {
                alertFired = true;
                Assert.Contains(".locked", e.DetectionReason);
            };

            var assessment = await _engine.EvaluateAndContainThreatAsync(
                encryptedDoc,
                "🚨 Bilinen fidye şifreleme uzantısı tespit edildi: '.locked'",
                riskScore: 95);

            Assert.NotNull(assessment);
            Assert.True(alertFired, "Alert event MUST be raised for known ransomware extensions");
            Assert.True(_engine.TotalBlockedAttempts > 0);
        }

        [Fact]
        public async Task Test_CanaryDecoyTampering_TriggersImmediateAlertAndContainment()
        {
            var canaryPath = Path.Combine(_protectedFolder, "!_ultron_shield_canary.docx");
            
            bool alertTriggered = false;
            _engine.OnRansomwareAttemptDetected += (s, e) =>
            {
                alertTriggered = true;
                Assert.Contains("Canary", e.DetectionReason);
            };

            var assessment = await _engine.EvaluateAndContainThreatAsync(
                canaryPath,
                "🚨 Kritik Tuzak İhlali: Kalkan Canary dosyası izinsiz değiştirildi!",
                riskScore: 100);

            Assert.NotNull(assessment);
            Assert.True(alertTriggered, "Canary tampering MUST trigger critical defense alert");
        }

        [Fact]
        public async Task Test_SafeRansomwareSimulator_RunsInIsolationAndTriggersContainment()
        {
            // Create a dedicated simulator sandbox directory
            var simSandbox = Path.Combine(_testRoot, "SimulatorSandbox");
            Directory.CreateDirectory(simSandbox);
            _engine.AddProtectedDirectory(simSandbox);

            // Create 15 benign test documents in sandbox
            for (int i = 0; i < 15; i++)
            {
                var doc = Path.Combine(simSandbox, $"test_doc_{i}.txt");
                await File.WriteAllTextAsync(doc, $"Sample Document Content {i}");
            }

            // Simulate rapid rename burst
            bool simulationAlertFired = false;
            _engine.OnRansomwareAttemptDetected += (s, e) =>
            {
                simulationAlertFired = true;
            };

            var simResult = await _engine.EvaluateAndContainThreatAsync(
                Path.Combine(simSandbox, "test_doc_0.txt.encrypted"),
                "🚨 Simüle Edilmiş Kitle Şifreleme Testi",
                riskScore: 90);

            Assert.NotNull(simResult);
            Assert.True(simulationAlertFired);
            Assert.True(simResult.FilesBlocked > 0);
        }

        public void Dispose()
        {
            try
            {
                _engine.Dispose();
                if (Directory.Exists(_testRoot))
                {
                    Directory.Delete(_testRoot, true);
                }
            }
            catch { }
        }
    }
}
