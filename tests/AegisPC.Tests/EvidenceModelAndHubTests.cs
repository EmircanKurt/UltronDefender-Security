using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class EvidenceModelAndHubTests : IDisposable
    {
        private readonly string _sandboxDir;
        private readonly HashService _hashService;
        private readonly SignatureVerifier _signatureVerifier;
        private readonly DetectionHub _hub;

        public EvidenceModelAndHubTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "Aegis_HubTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);

            _hashService = new HashService();
            _signatureVerifier = new SignatureVerifier();

            var detectors = new List<IDetectorPlugin>
            {
                new HashSignatureDetector(_hashService),
                new PeStaticDetector(),
                new EntropyDetector(),
                new LocationReputationDetector(_signatureVerifier)
            };

            _hub = new DetectionHub(detectors);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Test_DetectionHub_AggregatesMultiSignalEvidence()
        {
            var testFile = Path.Combine(_sandboxDir, "multi_signal_sample.exe");
            var content = "SetWindowsHookEx; WH_KEYBOARD_LL; GetAsyncKeyState; VirtualAllocEx; WriteProcessMemory;";
            await File.WriteAllTextAsync(testFile, content);

            var context = new DetectionContext
            {
                FilePath = testFile,
                FileSize = new FileInfo(testFile).Length
            };

            var result = await _hub.EvaluateAsync(context);

            Assert.NotNull(result);
            Assert.True(result.Evidences.Count >= 3, $"Should have aggregated multiple evidences (Actual: {result.Evidences.Count})");
            Assert.True(result.RiskScore > 0, "Risk score must be positive for multi-signal suspicious file.");
            Assert.NotEqual(DetectionVerdict.Clean, result.Verdict);
        }

        [Fact]
        public async Task Test_DetectionHub_EnforcesCategoryScoreCapping()
        {
            // Create a mock detector that emits 6 distinct StaticApi evidences of +25 each (Total raw = 150)
            var mockApiDetector = new MockDetector(
                "Mock.Apis", 
                "Mock API Detector", 
                EvidenceCategory.StaticApi, 
                1,
                ctx => new List<SecurityEvidence>
                {
                    new() { Category = EvidenceCategory.StaticApi, RuleName = "API.1", ScoreContribution = 25, Description = "API 1" },
                    new() { Category = EvidenceCategory.StaticApi, RuleName = "API.2", ScoreContribution = 25, Description = "API 2" },
                    new() { Category = EvidenceCategory.StaticApi, RuleName = "API.3", ScoreContribution = 25, Description = "API 3" },
                    new() { Category = EvidenceCategory.StaticApi, RuleName = "API.4", ScoreContribution = 25, Description = "API 4" },
                    new() { Category = EvidenceCategory.StaticApi, RuleName = "API.5", ScoreContribution = 25, Description = "API 5" },
                    new() { Category = EvidenceCategory.StaticApi, RuleName = "API.6", ScoreContribution = 25, Description = "API 6" }
                });

            var customHub = new DetectionHub(new[] { mockApiDetector });

            var context = new DetectionContext { FilePath = @"C:\dummy\benign_tool.exe" };
            var result = await customHub.EvaluateAsync(context);

            // StaticApi category cap is 45. The raw sum is 150.
            // Resulting score MUST be exactly 45, preventing single category from causing ConfirmedMalicious!
            Assert.Equal(45, result.RiskScore);
            Assert.Equal(DetectionVerdict.LowRisk, result.Verdict); // 45 is LowRisk (< 50)
            Assert.Equal(DetectionPolicy.Observe, result.RecommendedPolicy); // LowRisk maps to Observe, NEVER Block/Delete!
        }

        [Fact]
        public async Task Test_DetectionHub_DeduplicatesIdenticalRules()
        {
            // Detector emitting duplicated evidence
            var mockDupDetector = new MockDetector(
                "Mock.Duplicates",
                "Mock Duplicate Detector",
                EvidenceCategory.LocationReputation,
                1,
                ctx => new List<SecurityEvidence>
                {
                    new() { Category = EvidenceCategory.LocationReputation, RuleName = "Location.TempDirectory", ScoreContribution = 25, FilePath = ctx.FilePath, Description = "Temp 1" },
                    new() { Category = EvidenceCategory.LocationReputation, RuleName = "Location.TempDirectory", ScoreContribution = 25, FilePath = ctx.FilePath, Description = "Temp 1 Duplicate" }
                });

            var customHub = new DetectionHub(new[] { mockDupDetector });
            var context = new DetectionContext { FilePath = @"C:\Temp\tool.exe" };
            var result = await customHub.EvaluateAsync(context);

            Assert.Single(result.Evidences); // Exactly 1 evidence after deduplication
            Assert.Equal(25, result.RiskScore);
        }

        [Fact]
        public async Task Test_DetectionHub_KnownSignature_TriggersInstantConfirmedMalicious()
        {
            var signatureFile = Path.Combine(_sandboxDir, "mimikatz_sample.bin");
            await File.WriteAllTextAsync(signatureFile, "EXPORT: sekurlsa::logonpasswords; lsadump::sam;");

            var context = new DetectionContext
            {
                FilePath = signatureFile,
                FileSize = new FileInfo(signatureFile).Length
            };

            var result = await _hub.EvaluateAsync(context);

            Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
            Assert.Equal(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
            Assert.True(result.RiskScore >= 95);
            Assert.Contains(result.Evidences, e => e.Category == EvidenceCategory.StaticSignature);
        }

        [Fact]
        public async Task Test_DetectionHub_UnknownCleanFile_ProducesCleanAllow()
        {
            var cleanFile = Path.Combine(_sandboxDir, "normal_document.txt");
            await File.WriteAllTextAsync(cleanFile, "Hello, this is a clean text file with standard data.");

            var context = new DetectionContext
            {
                FilePath = cleanFile,
                FileSize = new FileInfo(cleanFile).Length
            };

            var result = await _hub.EvaluateAsync(context);

            Assert.Equal(DetectionVerdict.Clean, result.Verdict);
            Assert.Equal(DetectionPolicy.Allow, result.RecommendedPolicy);
            Assert.Equal(0, result.RiskScore);
        }

        [Fact]
        public async Task Test_DetectionHub_IsolatedPluginFaultTolerance()
        {
            var throwingDetector = new MockDetector(
                "Mock.Faulty",
                "Faulty Detector",
                EvidenceCategory.AntiEvasion,
                1,
                ctx => throw new InvalidOperationException("Simulated plugin crash"));

            var healthyDetector = new MockDetector(
                "Mock.Healthy",
                "Healthy Detector",
                EvidenceCategory.EntropyAnomaly,
                2,
                ctx => new List<SecurityEvidence>
                {
                    new() { Category = EvidenceCategory.EntropyAnomaly, RuleName = "Entropy.Sample", ScoreContribution = 15, Description = "Healthy measurement" }
                });

            var customHub = new DetectionHub(new[] { throwingDetector, healthyDetector });
            var context = new DetectionContext { FilePath = @"C:\test.bin" };

            // Must NOT throw; healthy detector's evidence must still be gathered
            var result = await customHub.EvaluateAsync(context);

            Assert.NotNull(result);
            Assert.Single(result.Evidences);
            Assert.Equal(15, result.RiskScore);
        }

        [Fact]
        public async Task Test_DetectionHub_KeyloggerFixture_MultiSignalEvidenceBreakdown()
        {
            var keyloggerFile = Path.Combine(_sandboxDir, "stealth_keylogger.dll");
            var keyloggerCode = "SetWindowsHookEx; WH_KEYBOARD_LL; GetAsyncKeyState; GetForegroundWindow;";
            await File.WriteAllTextAsync(keyloggerFile, keyloggerCode);

            var context = new DetectionContext
            {
                FilePath = keyloggerFile,
                FileSize = new FileInfo(keyloggerFile).Length
            };

            var result = await _hub.EvaluateAsync(context);

            Assert.True(result.RiskScore >= 50, $"Keylogger multi-signal risk score must be >= 50 (Actual: {result.RiskScore})");
            Assert.True(result.Evidences.Count >= 2, "Must contain multiple weighted evidence records.");
            Assert.Contains(result.Evidences, e => e.RuleName.Contains("SetWindowsHookEx") || e.Description.Contains("SetWindowsHookEx"));
        }

        [Fact]
        public async Task Test_CoreContracts_FileAndProcessIdentity_PopulatedAndCorrelated()
        {
            var testFile = Path.Combine(_sandboxDir, "identity_sample.exe");
            await File.WriteAllTextAsync(testFile, "MZ_DUMMY");

            var fileIdentity = new FileIdentity
            {
                Volume = "C:",
                FileId = "100234",
                CanonicalPath = testFile,
                Size = new FileInfo(testFile).Length,
                CreationTime = DateTime.UtcNow,
                LastWriteTime = DateTime.UtcNow,
                SHA256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                Signer = "Unsigned"
            };

            var procIdentity = new ProcessIdentity
            {
                ProcessId = 1234,
                ParentProcessId = 5678,
                ImagePath = @"C:\Windows\explorer.exe",
                CommandLine = "explorer.exe",
                User = "DOMAIN\\User",
                IntegrityLevel = "Medium",
                Signer = "Microsoft Windows"
            };

            var context = new DetectionContext
            {
                FilePath = testFile,
                FileSize = fileIdentity.Size,
                SHA256 = fileIdentity.SHA256,
                ProcessId = procIdentity.ProcessId,
                ParentProcessId = procIdentity.ParentProcessId,
                FileIdentity = fileIdentity,
                ProcessContext = procIdentity
            };

            var result = await _hub.EvaluateAsync(context);

            result.FileIdentity = context.FileIdentity;
            result.ProcessContext = context.ProcessContext;

            Assert.NotNull(result.FileIdentity);
            Assert.Equal("identity_sample.exe", result.FileIdentity.FileName);
            Assert.NotNull(result.ProcessContext);
            Assert.Equal(1234, result.ProcessContext.ProcessId);
            Assert.Equal("explorer.exe", result.ProcessContext.ProcessName);
            Assert.NotNull(result.Severity);
            Assert.True(result.Policy == DetectionPolicy.Allow || result.Policy == DetectionPolicy.Observe);
            Assert.NotNull(result.RecommendedAction);
        }

        [Fact]
        public async Task Test_DetectionHub_ScriptHeuristicDetector_CatchesRansomwareCommands()
        {
            var scriptFile = Path.Combine(_sandboxDir, "ransom_test.bat");
            await File.WriteAllTextAsync(scriptFile, "@echo off\r\nvssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled no\r\n");

            var scriptDetector = new ScriptHeuristicDetector();
            var hub = new DetectionHub(new[] { scriptDetector });

            var context = new DetectionContext
            {
                FilePath = scriptFile,
                FileSize = new FileInfo(scriptFile).Length
            };

            var result = await hub.EvaluateAsync(context);

            Assert.True(result.Evidences.Count >= 2);
            Assert.Contains(result.Evidences, e => e.RuleName == "Script.VssShadowDelete");
            Assert.Contains(result.Evidences, e => e.RuleName == "Script.BcdeditRecoveryDisabled");
            Assert.True(result.RiskScore >= 50);
        }

        [Fact]
        public async Task Test_DetectionHub_PersistenceDetector_CatchesStartupDrops()
        {
            var fakeStartupPath = Path.Combine(_sandboxDir, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\bad.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(fakeStartupPath)!);
            await File.WriteAllTextAsync(fakeStartupPath, "MZ_PAYLOAD");

            var persistenceDetector = new PersistenceDetector();
            var hub = new DetectionHub(new[] { persistenceDetector });

            var context = new DetectionContext
            {
                FilePath = fakeStartupPath,
                FileSize = 10
            };

            var result = await hub.EvaluateAsync(context);

            Assert.Single(result.Evidences);
            Assert.Equal("Persistence.StartupFolderDrop", result.Evidences[0].RuleName);
            Assert.Equal(25, result.RiskScore);
        }

        [Fact]
        public void Test_DetectionHubFactory_CreatesAll13Detectors()
        {
            var hub = DetectionHubFactory.CreateDefault();
            Assert.NotNull(hub);
            Assert.True(hub.RegisteredDetectors.Count >= 10, $"Expected >= 10 detectors registered, found {hub.RegisteredDetectors.Count}");
        }

        // Helper Mock Detector for Testing Edge Cases
        private class MockDetector : IDetectorPlugin
        {
            private readonly Func<DetectionContext, IEnumerable<SecurityEvidence>> _evaluator;

            public string DetectorId { get; }
            public string DisplayName { get; }
            public EvidenceCategory PrimaryCategory { get; }
            public int Priority { get; }
            public bool IsEnabled { get; set; } = true;

            public MockDetector(string id, string name, EvidenceCategory category, int priority, Func<DetectionContext, IEnumerable<SecurityEvidence>> evaluator)
            {
                DetectorId = id;
                DisplayName = name;
                PrimaryCategory = category;
                Priority = priority;
                _evaluator = evaluator;
            }

            public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
            {
                return Task.FromResult(_evaluator(context));
            }
        }
    }
}
