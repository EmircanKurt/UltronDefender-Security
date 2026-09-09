using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class SelfDetectionExclusionTests : IDisposable
    {
        private readonly string _testDir;

        public SelfDetectionExclusionTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "SelfDetTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testDir))
                {
                    Directory.Delete(_testDir, recursive: true);
                }
            }
            catch { }
        }

        [Theory]
        [InlineData(@"C:\Arbitrary\Folder\AegisPC.Security.pdb")]
        [InlineData(@"C:\Arbitrary\Folder\UltronDefender.exe")]
        [InlineData(@"C:\Arbitrary\Folder\Ultron.Core.dll")]
        [InlineData(@"C:\Users\PC\Documents\gemini virüs program\AegisPC_Staging\Service\AegisPC.Security.pdb")]
        [InlineData(@"C:\Users\PC\Documents\gemini virüs program\AegisPC_App_Optimized\Service\AegisPC.Security.pdb")]
        [InlineData(@"C:\ProgramData\UltronDefender\signatures.db")]
        [InlineData(@"C:\Program Files\UltronDefender\UltronDefender.exe")]
        [InlineData(@"C:\Users\User\AppData\Local\AegisPC\cache.db")]
        public void IsSelfOwnedPath_IdentifiesOwnBinariesAndFolders(string path)
        {
            Assert.True(ScanFilterPolicy.IsSelfOwnedPath(path));
            Assert.True(FileScannerService.IsSelfOwnedPath(path));
        }

        [Fact]
        public void SafeMediaExtensions_IncludesPdbAndSymbols()
        {
            Assert.Contains(".pdb", ScanFilterPolicy.SafeMediaExtensions);
            Assert.Contains(".idb", ScanFilterPolicy.SafeMediaExtensions);
            Assert.Contains(".ilk", ScanFilterPolicy.SafeMediaExtensions);
            Assert.Contains(".lib", ScanFilterPolicy.SafeMediaExtensions);
        }

        [Fact]
        public async Task RealTimeVerdictProcessor_NeverFlagsPdbFile()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskEngine = new RiskScoringEngine();

            var processor = new RealTimeVerdictProcessor(
                hashService,
                sigVerifier,
                riskEngine);

            // Create a fake PDB file with strings that look like malware APIs and EICAR
            string fakePdbPath = Path.Combine(_testDir, "AegisPC.Security.pdb");
            await File.WriteAllTextAsync(fakePdbPath, "VirtualAllocEx WriteProcessMemory NtUnmapViewOfSection CreateRemoteThread EICAR-STANDARD-ANTIVIRUS-TEST-FILE!");

            var result = await processor.InspectFileAsync(fakePdbPath);

            Assert.Equal(RealTimeVerdict.Clean, result.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, result.RecommendedPolicy);
            Assert.Equal(0, result.RiskScore);
        }

        [Fact]
        public async Task FileScannerService_NeverFlagsSelfOwnedPdb()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskEngine = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();

            var scanner = new FileScannerService(
                hashService,
                sigVerifier,
                riskEngine,
                allowlist,
                findingService);

            string fakePdbPath = Path.Combine(_testDir, "AegisPC.Security.pdb");
            await File.WriteAllTextAsync(fakePdbPath, "VirtualAllocEx WriteProcessMemory NtUnmapViewOfSection CreateRemoteThread");

            var finding = await scanner.ScanFileAsync(fakePdbPath);

            // Self-owned file should immediately return null (skipped)
            Assert.Null(finding);
        }

        [Fact]
        public async Task StartupSecuritySweep_SkipsSelfPdbAndDoesNotQuarantine()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskEngine = new RiskScoringEngine();
            var findingService = new SecurityFindingService();
            var allowlist = new AllowlistService(hashService);
            string vaultDir = Path.Combine(_testDir, "Vault");
            var quarantine = new QuarantineService(hashService, null, null, vaultDir);

            var scanner = new FileScannerService(
                hashService,
                sigVerifier,
                riskEngine,
                allowlist,
                findingService);

            var rtEngine = new RealTimeProtectionEngine(
                scanner,
                hashService,
                sigVerifier,
                riskEngine,
                quarantine,
                findingService);

            var sweep = new StartupSecuritySweepService(rtEngine, quarantine);

            string stagingDir = Path.Combine(_testDir, "AegisPC_Staging");
            Directory.CreateDirectory(stagingDir);

            string selfPdb = Path.Combine(stagingDir, "AegisPC.Security.pdb");
            await File.WriteAllTextAsync(selfPdb, "VirtualAllocEx WriteProcessMemory NtUnmapViewOfSection CreateRemoteThread");

            var result = await sweep.RunSweepAsync(new[] { _testDir });

            // Must not quarantine AegisPC.Security.pdb
            Assert.Equal(0, result.ThreatsCount);
            Assert.True(File.Exists(selfPdb), "AegisPC.Security.pdb must not be deleted or quarantined!");
        }
    }
}
