using System;
using System.IO;
using System.Linq;
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
    public class KeyloggerDetectionTests : IDisposable
    {
        private readonly string _testSandboxDir;
        private readonly HashService _hashService;
        private readonly SignatureVerifier _sigVerifier;
        private readonly IDetectionHub _detectionHub;

        public KeyloggerDetectionTests()
        {
            _testSandboxDir = Path.Combine(Path.GetTempPath(), "AegisKeylogTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testSandboxDir);

            _hashService = new HashService();
            _sigVerifier = new SignatureVerifier();
            _detectionHub = DetectionHubFactory.CreateDefault(_hashService, _sigVerifier);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testSandboxDir))
                {
                    Directory.Delete(_testSandboxDir, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Test_SuspiciousApiImports_ProducesExplainableEvidence()
        {
            // Simulated binary path with keyboard hooking indicators
            var samplePath = Path.Combine(_testSandboxDir, "keylogger_sample.exe");
            // Writing simulated PE payload containing SetWindowsHookEx & GetKeyboardState text patterns
            await File.WriteAllTextAsync(samplePath, "MZ...SetWindowsHookExW...GetKeyboardState...ToUnicode...WH_KEYBOARD_LL");

            var context = new DetectionContext
            {
                FilePath = samplePath,
                SHA256 = await _hashService.ComputeSha256Async(samplePath),
                FileSize = new FileInfo(samplePath).Length,
                CorrelationId = Guid.NewGuid().ToString("N")
            };

            var result = await _detectionHub.EvaluateAsync(context);

            Assert.NotNull(result);
            Assert.True(result.Evidences.Count > 0);
            
            // Check that static API evidences are categorized and scored
            var apiEvidences = result.Evidences.Where(e => e.Category == EvidenceCategory.StaticApi).ToList();
            Assert.NotEmpty(apiEvidences);
            Assert.All(apiEvidences, e =>
            {
                Assert.False(string.IsNullOrWhiteSpace(e.RuleName));
                Assert.False(string.IsNullOrWhiteSpace(e.Description));
                Assert.True(e.ScoreContribution > 0);
            });
        }
    }
}
