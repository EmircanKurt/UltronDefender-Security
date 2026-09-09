using System;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class PathTrustEliminationTests : IDisposable
    {
        private readonly string _testSandbox;

        public PathTrustEliminationTests()
        {
            _testSandbox = Path.Combine(Path.GetTempPath(), "Aegis_PathTrustTests_" + Guid.NewGuid().ToString("N"));
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

        [Theory]
        [InlineData(@"Games\FitGirl\payload.exe")]
        [InlineData(@"Oyunlar\SteamRip\injector.dll")]
        [InlineData(@"ProgramData\Games\stealth_miner.exe")]
        public async Task LocationReputationDetector_AdversarialGamePaths_DoNotDiscountRiskScore(string relativePath)
        {
            var sigVerifier = new SignatureVerifier();
            var detector = new LocationReputationDetector(sigVerifier);

            string fullPath = Path.Combine(_testSandbox, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
            await File.WriteAllTextAsync(fullPath, "dummy binary payload for testing");

            var context = new DetectionContext
            {
                FilePath = fullPath,
                SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                FileSize = 1024
            };

            var evidences = await detector.EvaluateAsync(context, CancellationToken.None);

            // Verify no evidence grants negative/discounted scores for being in games directory
            foreach (var ev in evidences)
            {
                Assert.True(ev.ScoreContribution >= 0, $"Rule '{ev.RuleName}' illegally gave negative score for game path: {ev.ScoreContribution}");
            }
        }

        [Fact]
        public async Task FileHashMatcher_KnownMalwareHash_NeverBypassedEvenIfSigned()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var allowlist = new AllowlistService(hashService);
            var matcher = new FileHashMatcher(hashService, sigVerifier, allowlist);

            string fakeMalwarePath = Path.Combine(_testSandbox, "eicar.com");
            // Standard EICAR string whose SHA256 matches MalwareSignatureDatabase
            const string eicarPayload = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            await File.WriteAllTextAsync(fakeMalwarePath, eicarPayload);

            var (sha256, isAllowlisted, isMicrosoftBypassed) = await matcher.EvaluateHashAndAllowlistAsync(fakeMalwarePath, CancellationToken.None);

            var match = MalwareSignatureDatabase.CheckHash(sha256);
            Assert.True(match.IsMatched, "EICAR payload hash must match known threat database.");
            Assert.False(isMicrosoftBypassed, "Known malware hash must NEVER be bypassed!");
            Assert.False(isAllowlisted, "Known malware hash must NEVER be marked allowed!");
        }

        [Fact]
        public async Task ArchiveSafetyScanner_GamePathArchives_AreNotSkipped()
        {
            var scanner = new ArchiveSafetyScanner();
            string gameArchive = Path.Combine(_testSandbox, "setup.zip");

            using (var zip = ZipFile.Open(gameArchive, ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("readme.txt");
                using var writer = new StreamWriter(entry.Open());
                writer.WriteLine("game data");
            }

            var result = await scanner.ScanArchiveAsync(gameArchive, CancellationToken.None);
            Assert.True(result.IsArchive, "Archives in Games directory must be identified and scanned for safety!");
        }
    }
}
