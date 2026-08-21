using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using Xunit;

namespace AegisPC.Tests
{
    public class ScoringRegressionTests
    {
        [Fact]
        public async Task Test01_SignedNormalApplication_ShouldBeClean()
        {
            var hub = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Program Files\Google\Chrome\chrome.exe" };
            
            hub.RegisterDetector(new MockDetector("MockSig", EvidenceCategory.DigitalCertificate, "DigitalSignature", 0, "Valid commercial certificate"));

            var result = await hub.EvaluateAsync(context);
            Assert.True(result.RiskScore <= 10);
            Assert.Equal(DetectionVerdict.Clean, result.Verdict);
        }

        [Fact]
        public async Task Test02_UnsignedNormalExecutable_ShouldBeCleanOrLowRisk()
        {
            var hub = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Tools\clean_utility.exe" };
            
            hub.RegisterDetector(new MockDetector("MockUnsigned", EvidenceCategory.DigitalCertificate, "DigitalSignature", 10, "Unsigned binary"));

            var result = await hub.EvaluateAsync(context);
            Assert.Equal(10, result.RiskScore);
            Assert.Equal(DetectionVerdict.Clean, result.Verdict);
        }

        [Fact]
        public async Task Test03_HighEntropyBenignInstaller_ShouldBeSuspiciousNotMalicious()
        {
            var hub = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Downloads\installer.exe" };
            
            hub.RegisterDetector(new MockDetector("MockUnsigned", EvidenceCategory.DigitalCertificate, "DigitalSignature", 10, "Unsigned binary"));
            hub.RegisterDetector(new MockDetector("MockEntropy", EvidenceCategory.EntropyAnomaly, "Packing", 35, "High entropy 7.92"));
            hub.RegisterDetector(new MockDetector("MockRsrcEntropy", EvidenceCategory.EntropyAnomaly, "Packing", 25, "High .rsrc entropy 7.81"));
            hub.RegisterDetector(new MockDetector("MockTls", EvidenceCategory.StaticPeStructure, "PeStructure", 20, "TLS callback"));

            var result = await hub.EvaluateAsync(context);
            // Deduplicated Packing: 35 + Floor(25/4) = 41. Capped at Entropy Cap (35).
            // DigitalCertificate: 10.
            // StaticPeStructure: 20.
            // Total = 35 + 10 + 20 = 65.
            Assert.Equal(65, result.RiskScore);
            Assert.Equal(DetectionVerdict.Suspicious, result.Verdict);
            Assert.Equal(DetectionPolicy.Warn, result.RecommendedPolicy);
            Assert.NotEqual(DetectionVerdict.ConfirmedMalicious, result.Verdict);
        }

        [Fact]
        public async Task Test04_SingleSuspiciousApi_ShouldBeCleanOrLowRisk()
        {
            var hub = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Dev\macro_tool.exe" };
            
            hub.RegisterDetector(new MockDetector("MockAsyncKey", EvidenceCategory.StaticApi, "KeyloggerApi", 15, "GetAsyncKeyState"));

            var result = await hub.EvaluateAsync(context);
            Assert.Equal(15, result.RiskScore);
            Assert.Equal(DetectionVerdict.Clean, result.Verdict);
        }

        [Fact]
        public async Task Test05_MultiSignalCorrelatedKeyloggerApis_ShouldIncreaseRisk()
        {
            var hub = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Suspicious\hook.exe" };
            
            hub.RegisterDetector(new MockDetector("MockHook", EvidenceCategory.StaticApi, "KeyloggerApi", 25, "SetWindowsHookEx"));
            hub.RegisterDetector(new MockDetector("MockKeyboardLl", EvidenceCategory.StaticApi, "KeyloggerApi", 20, "WH_KEYBOARD_LL"));
            hub.RegisterDetector(new MockDetector("MockAsyncKey", EvidenceCategory.StaticApi, "KeyloggerApi", 15, "GetAsyncKeyState"));

            var result = await hub.EvaluateAsync(context);
            // Dominant 25 + Floor((20+15)/4) = 25 + 8 = 33.
            Assert.True(result.RiskScore >= 30 && result.RiskScore <= 45);
        }

        [Fact]
        public async Task Test06_EicarStandardTestFile_ShouldBeConfirmedMalicious()
        {
            var hub = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Tests\eicar.com" };
            
            hub.RegisterDetector(new MockDetector("MockEicar", EvidenceCategory.StaticSignature, "KnownThreatSignature", 100, "EICAR-Standard-AV-Test", EvidenceConfidence.Absolute));

            var result = await hub.EvaluateAsync(context);
            Assert.Equal(100, result.RiskScore);
            Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
            Assert.Equal(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
        }

        [Fact]
        public async Task Test07_KnownRansomwareHash_ShouldBeConfirmedMalicious()
        {
            var hub = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Samples\wannacry.exe" };
            
            hub.RegisterDetector(new MockDetector("MockWannaCry", EvidenceCategory.StaticSignature, "KnownThreatSignature", 100, "Trojan:Ransom.Win32.WannaCry", EvidenceConfidence.Absolute));

            var result = await hub.EvaluateAsync(context);
            Assert.Equal(100, result.RiskScore);
            Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
            Assert.Equal(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
        }

        [Fact]
        public async Task Test08_KeyloggerInTempWithPersistence_ShouldBeConfirmedMalicious()
        {
            var hub = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Users\User\AppData\Local\Temp\svchost.exe" };
            
            hub.RegisterDetector(new MockDetector("MockHook", EvidenceCategory.StaticApi, "KeyloggerApi", 40, "Keylogger APIs"));
            hub.RegisterDetector(new MockDetector("MockTemp", EvidenceCategory.LocationReputation, "DropZone", 25, "Temp directory"));
            hub.RegisterDetector(new MockDetector("MockPersist", EvidenceCategory.Persistence, "Persistence", 30, "Run key startup"));
            hub.RegisterDetector(new MockDetector("MockUnsigned", EvidenceCategory.DigitalCertificate, "DigitalSignature", 10, "Unsigned binary"));

            var result = await hub.EvaluateAsync(context);
            Assert.True(result.RiskScore >= 85);
            Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
        }

        [Fact]
        public async Task Test09_MicrosoftSignedSystemFile_ShouldHaveZeroRiskScore()
        {
            var hub = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Windows\System32\cmd.exe" };
            
            hub.RegisterDetector(new MockDetector("ValidMicrosoft.Certificate", EvidenceCategory.DigitalCertificate, "DigitalSignature", 0, "ValidMicrosoft certificate in System32"));
            hub.RegisterDetector(new MockDetector("MockEntropy", EvidenceCategory.EntropyAnomaly, "Packing", 30, "Compressed system code"));

            var result = await hub.EvaluateAsync(context);
            Assert.Equal(0, result.RiskScore);
            Assert.Equal(DetectionVerdict.Clean, result.Verdict);
        }

        [Fact]
        public async Task Test10_MalwareImpersonatingUltronName_ShouldStillBeDetected()
        {
            var hub = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Users\User\Downloads\UltronDefender_Setup_v3.0.exe" };
            
            hub.RegisterDetector(new MockDetector("MockMimikatz", EvidenceCategory.StaticSignature, "KnownThreatSignature", 100, "Mimikatz Credential Dumper", EvidenceConfidence.Absolute));

            var result = await hub.EvaluateAsync(context);
            Assert.Equal(100, result.RiskScore);
            Assert.Equal(DetectionVerdict.ConfirmedMalicious, result.Verdict);
            Assert.Equal(DetectionPolicy.BlockAndQuarantine, result.RecommendedPolicy);
        }

        [Fact]
        public async Task MonotonicityTest_AddingSuspiciousEvidence_ShouldNeverDecreaseScore()
        {
            var hub1 = new DetectionHub();
            var context = new DetectionContext { FilePath = @"C:\Sample\test.exe" };
            hub1.RegisterDetector(new MockDetector("Ev1", EvidenceCategory.StaticApi, "ApiGroup", 20, "Suspicious API 1"));

            var res1 = await hub1.EvaluateAsync(context);

            var hub2 = new DetectionHub();
            hub2.RegisterDetector(new MockDetector("Ev1", EvidenceCategory.StaticApi, "ApiGroup", 20, "Suspicious API 1"));
            hub2.RegisterDetector(new MockDetector("Ev2", EvidenceCategory.LocationReputation, "DropZone", 25, "Temp Path"));

            var res2 = await hub2.EvaluateAsync(context);

            Assert.True(res2.RiskScore >= res1.RiskScore, $"Monotonicity violation: res1={res1.RiskScore}, res2={res2.RiskScore}");
        }

        private class MockDetector : IDetectorPlugin
        {
            public string DetectorId => Name;
            public string DisplayName => Name;
            public EvidenceCategory PrimaryCategory { get; }
            public string CorrelationGroup { get; }
            public int Priority => 10;
            public bool IsEnabled { get; set; } = true;
            public string Name { get; }
            public int Score { get; }
            public string Description { get; }
            public EvidenceConfidence Confidence { get; }

            public MockDetector(string name, EvidenceCategory cat, string correlationGroup, int score, string desc, EvidenceConfidence conf = EvidenceConfidence.Medium)
            {
                Name = name;
                PrimaryCategory = cat;
                CorrelationGroup = correlationGroup;
                Score = score;
                Description = desc;
                Confidence = conf;
            }

            public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, System.Threading.CancellationToken cancellationToken = default)
            {
                var list = new List<SecurityEvidence>
                {
                    new SecurityEvidence
                    {
                        RuleName = Name,
                        Category = PrimaryCategory,
                        CorrelationGroup = CorrelationGroup,
                        ScoreContribution = Score,
                        Description = Description,
                        Confidence = Confidence,
                        FilePath = context.FilePath
                    }
                };
                return Task.FromResult<IEnumerable<SecurityEvidence>>(list);
            }
        }
    }
}
