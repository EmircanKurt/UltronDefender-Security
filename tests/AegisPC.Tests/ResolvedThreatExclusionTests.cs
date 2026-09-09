using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class ResolvedThreatExclusionTests : IDisposable
    {
        private readonly string _testSandbox;
        private readonly HashService _hashService;
        private readonly SignatureVerifier _sigVerifier;
        private readonly RiskScoringEngine _scoring;
        private readonly MockSecurityFindingService _findingService;
        private readonly AllowlistService _allowlist;
        private readonly FileScannerService _scanner;

        public ResolvedThreatExclusionTests()
        {
            _testSandbox = Path.Combine(Path.GetTempPath(), "ResolvedThreatTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testSandbox);

            _hashService = new HashService();
            _sigVerifier = new SignatureVerifier();
            _scoring = new RiskScoringEngine();
            _findingService = new MockSecurityFindingService();
            _allowlist = new AllowlistService(_hashService);
            _scanner = new FileScannerService(_hashService, _sigVerifier, _scoring, _allowlist, _findingService);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testSandbox))
                {
                    Directory.Delete(_testSandbox, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task AllowlistService_PathIndexing_MatchesNormalizedPath()
        {
            // 1. Arrange
            var samplePath = Path.Combine(_testSandbox, "test_file.exe");
            await File.WriteAllTextAsync(samplePath, "Sample content for path matching");

            // 2. Act: Add by file path
            var entry = new AllowlistEntry
            {
                FilePath = samplePath,
                FileName = Path.GetFileName(samplePath),
                Reason = "Kullanıcı tarafından çözüldü olarak işaretlendi.",
                AddedBy = "Kullanıcı (Çözüldü)",
                AddedAt = DateTime.UtcNow,
                IsActive = true
            };
            await _allowlist.AddToAllowlistAsync(entry);

            // 3. Assert: Both exact path and alternative case match
            bool directMatch = await _allowlist.IsPathAllowlistedAsync(samplePath);
            bool upperMatch = await _allowlist.IsPathAllowlistedAsync(samplePath.ToUpperInvariant());
            bool lowerMatch = await _allowlist.IsPathAllowlistedAsync(samplePath.ToLowerInvariant());

            Assert.True(directMatch, "AllowlistService should match exact path.");
            Assert.True(upperMatch, "AllowlistService should match path case-insensitively (upper).");
            Assert.True(lowerMatch, "AllowlistService should match path case-insensitively (lower).");
        }

        [Fact]
        public async Task ResolvedThreat_WhenMarkedResolved_IsExcludedFromSubsequentScans()
        {
            // 1. Arrange: Create a known threat file (EICAR) in the test directory
            var threatFilePath = Path.Combine(_testSandbox, "eicar_threat_sample.com");
            const string eicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            await File.WriteAllTextAsync(threatFilePath, eicarContent);

            // 2. Act (Initial Scan): Scan without allowlist -> Must detect threat
            var initialFinding = await _scanner.ScanFileAsync(threatFilePath);
            var initialDetailed = await _scanner.ScanFileDetailedAsync(threatFilePath, TimeSpan.FromSeconds(10));

            Assert.NotNull(initialFinding);
            Assert.NotNull(initialDetailed.Finding);
            Assert.Contains("EICAR", initialFinding.Title);

            // 3. Act: Simulate user marking this threat as "Çözüldü" (Resolved / Allowlisted)
            var resolvedEntry = new AllowlistEntry
            {
                FilePath = threatFilePath,
                FileName = Path.GetFileName(threatFilePath),
                SHA256 = initialFinding.SHA256 ?? string.Empty,
                Reason = "Kullanıcı tarafından çözüldü olarak işaretlendi.",
                AddedBy = "Kullanıcı (Çözüldü)",
                AddedAt = DateTime.UtcNow,
                IsActive = true
            };
            await _allowlist.AddToAllowlistAsync(resolvedEntry);

            // Verify path is now recognized as allowlisted
            bool isAllowlisted = await _allowlist.IsPathAllowlistedAsync(threatFilePath);
            Assert.True(isAllowlisted, "Threat file path must be allowlisted after resolution.");

            // 4. Act (Subsequent Scan): Rescan the same threat file -> Must NOT encounter the threat again
            var subsequentFinding = await _scanner.ScanFileAsync(threatFilePath);
            var subsequentDetailed = await _scanner.ScanFileDetailedAsync(threatFilePath, TimeSpan.FromSeconds(10));

            // 5. Assert: Subsequent scans return null (clean/ignored)
            Assert.Null(subsequentFinding);
            Assert.Null(subsequentDetailed.Finding);
            Assert.Equal(FileScanOutcome.Success, subsequentDetailed.Outcome);
        }

        [Fact]
        public async Task ResolvedThreat_DirectoryScan_BypassesResolvedThreatFiles()
        {
            // 1. Arrange: Create directory with 1 clean file and 1 threat file
            var cleanFile = Path.Combine(_testSandbox, "clean_file.txt");
            await File.WriteAllTextAsync(cleanFile, "Just a clean normal text file");

            var threatFile = Path.Combine(_testSandbox, "bad_payload.com");
            const string eicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            await File.WriteAllTextAsync(threatFile, eicarContent);

            // Pre-register threatFile as resolved/allowlisted
            await _allowlist.AddToAllowlistAsync(new AllowlistEntry
            {
                FilePath = threatFile,
                FileName = Path.GetFileName(threatFile),
                Reason = "Kullanıcı tarafından çözüldü olarak işaretlendi.",
                IsActive = true
            });

            // 2. Act: Scan the threat file
            var threatResult = await _scanner.ScanFileAsync(threatFile);
            var cleanResult = await _scanner.ScanFileAsync(cleanFile);

            // 3. Assert: Neither produces findings
            Assert.Null(threatResult);
            Assert.Null(cleanResult);
        }
    }
}
