using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Policy;
using AegisPC.Contracts.Safety;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Database;
using AegisPC.Security.Policy;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class QuarantineRestoreTests : IDisposable
    {
        private readonly string _testSandboxDir;
        private readonly string _vaultDir;
        private readonly string _dbPath;
        private readonly DatabaseService _databaseService;
        private readonly ExclusionService _exclusionService;
        private readonly IHashService _hashService;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IAllowlistService _allowlistService;
        private readonly FileHashMatcher _fileHashMatcher;

        public QuarantineRestoreTests()
        {
            _testSandboxDir = Path.Combine(Path.GetTempPath(), "QuarRestoreTests_" + Guid.NewGuid().ToString("N"));
            _vaultDir = Path.Combine(_testSandboxDir, "Vault");
            Directory.CreateDirectory(_testSandboxDir);
            Directory.CreateDirectory(_vaultDir);

            _dbPath = Path.Combine(_testSandboxDir, "quar_test.db");
            _databaseService = new DatabaseService(_dbPath);
            _databaseService.InitializeAsync().GetAwaiter().GetResult();

            _exclusionService = new ExclusionService(_databaseService);
            _exclusionService.InitializeAsync().GetAwaiter().GetResult();

            _hashService = new HashService();
            _signatureVerifier = new SignatureVerifier();
            _allowlistService = new AllowlistService(_hashService, null, _exclusionService);
            _fileHashMatcher = new FileHashMatcher(_hashService, _signatureVerifier, _allowlistService, _exclusionService);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testSandboxDir))
                {
                    Directory.Delete(_testSandboxDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Restore_WhenOriginalDirectoryWasDeleted_RecreatesDirectoryAndRestoresFile()
        {
            // Arrange
            var customSubDir = Path.Combine(_testSandboxDir, "Deep", "Nested", "Directory");
            Directory.CreateDirectory(customSubDir);

            var sampleFile = Path.Combine(customSubDir, "sample_threat.dll");
            var originalContent = "MALWARE_PAYLOAD_EICAR_BYTE_STREAM_ABC_123";
            await File.WriteAllTextAsync(sampleFile, originalContent);

            var quarantine = new QuarantineService(
                _hashService,
                customVaultDir: _vaultDir,
                exclusionService: _exclusionService,
                fileHashMatcher: _fileHashMatcher);

            bool quarantined = await quarantine.QuarantineFileAsync(sampleFile, "Trojan.Generic");
            Assert.True(quarantined);
            Assert.False(File.Exists(sampleFile));

            var items = await quarantine.GetQuarantinedItemsAsync();
            Assert.Single(items);
            var entry = items[0];

            // Simulate user or system deleting the original nested folder
            Directory.Delete(Path.Combine(_testSandboxDir, "Deep"), true);
            Assert.False(Directory.Exists(customSubDir));

            // Act
            bool restored = await quarantine.RestoreFileAsync(entry.Id);

            // Assert
            Assert.True(restored, $"Restore should succeed even if directory was deleted. Error: {quarantine.LastError}");
            Assert.True(Directory.Exists(customSubDir), "Original directory should be automatically recreated.");
            Assert.True(File.Exists(sampleFile), "Restored file must exist at original path.");
            var contentOnDisk = await File.ReadAllTextAsync(sampleFile);
            Assert.Equal(originalContent, contentOnDisk);

            var updatedEntry = await quarantine.GetItemByIdAsync(entry.Id);
            Assert.NotNull(updatedEntry);
            Assert.Equal(QuarantineStatus.Restored, updatedEntry!.Status);
        }

        [Fact]
        public async Task Restore_WhenTargetFileIsLocked_ReturnsFalseAndSetsLockedLastError()
        {
            // Arrange
            var sampleFile = Path.Combine(_testSandboxDir, "locked_target.exe");
            await File.WriteAllTextAsync(sampleFile, "CONTENT_TO_LOCK");

            var quarantine = new QuarantineService(
                _hashService,
                customVaultDir: _vaultDir,
                exclusionService: _exclusionService,
                fileHashMatcher: _fileHashMatcher);

            bool quarantined = await quarantine.QuarantineFileAsync(sampleFile, "Spyware.Keylogger");
            Assert.True(quarantined);

            var items = await quarantine.GetQuarantinedItemsAsync();
            var entry = items[0];

            // Recreate file at original location and hold an exclusive lock
            using (var lockStream = new FileStream(sampleFile, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                lockStream.Write(new byte[] { 1, 2, 3 });
                lockStream.Flush();

                // Act
                bool restored = await quarantine.RestoreFileAsync(entry.Id);

                // Assert
                Assert.False(restored, "Restore should fail when target file is locked by another process.");
                Assert.NotNull(quarantine.LastError);
                Assert.Contains("kullanılıyor", quarantine.LastError, StringComparison.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public async Task Restore_WhenVaultContainerCorrupted_MarksStatusAsCorruptedAndSetsLastError()
        {
            // Arrange
            var sampleFile = Path.Combine(_testSandboxDir, "corrupted_vault_test.exe");
            await File.WriteAllTextAsync(sampleFile, "INTEGRITY_CHECK_FILE_BYTES");

            var quarantine = new QuarantineService(
                _hashService,
                customVaultDir: _vaultDir,
                exclusionService: _exclusionService,
                fileHashMatcher: _fileHashMatcher);

            bool quarantined = await quarantine.QuarantineFileAsync(sampleFile, "Ransom.WannaCry");
            Assert.True(quarantined);

            var items = await quarantine.GetQuarantinedItemsAsync();
            var entry = items[0];

            // Deliberately corrupt vault file on disk
            Assert.True(File.Exists(entry.QuarantinePath));
            await File.WriteAllBytesAsync(entry.QuarantinePath, Encoding.UTF8.GetBytes("INVALID_VAULT_HEADER_GARBAGE_DATA_CORRUPT"));

            // Act
            bool restored = await quarantine.RestoreFileAsync(entry.Id);

            // Assert
            Assert.False(restored, "Restore must fail on corrupted vault file.");
            Assert.NotNull(quarantine.LastError);
            Assert.Contains("kasa kaydı bozuk", quarantine.LastError, StringComparison.OrdinalIgnoreCase);

            var item = await quarantine.GetItemByIdAsync(entry.Id);
            Assert.NotNull(item);
            Assert.Equal(QuarantineStatus.Corrupted, item!.Status);
        }

        [Fact]
        public async Task Restore_Grants5MinuteTemporaryExclusion_AndPreventsPolicyEngineReQuarantineLoop()
        {
            // Arrange: Setup Quarantine, ExclusionService and PolicyEngine
            var sampleFile = Path.Combine(_testSandboxDir, "loop_test_malware.exe");
            var originalContent = "MALICIOUS_THREAT_SIMULATION_BYTES_999";
            await File.WriteAllTextAsync(sampleFile, originalContent);
            var sha256 = await _hashService.ComputeSha256Async(sampleFile);

            var quarantine = new QuarantineService(
                _hashService,
                customVaultDir: _vaultDir,
                exclusionService: _exclusionService,
                fileHashMatcher: _fileHashMatcher);

            bool quarantined = await quarantine.QuarantineFileAsync(sampleFile, "Backdoor.Trojan");
            Assert.True(quarantined);
            Assert.False(File.Exists(sampleFile));

            var items = await quarantine.GetQuarantinedItemsAsync();
            var entry = items[0];

            // Act: Restore the file
            bool restored = await quarantine.RestoreFileAsync(entry.Id);
            Assert.True(restored);
            Assert.True(File.Exists(sampleFile));

            // Verify: 1. Temporary exclusion window is active
            bool isExcluded = _exclusionService.IsExcluded(sampleFile, sha256);
            Assert.True(isExcluded, "Restored file must be granted a temporary exclusion to avoid re-detection loop.");
            Assert.False(_exclusionService.IsExcluded(sampleFile), "A path without verified content must not bypass scanning.");
            Assert.False(_exclusionService.IsExcluded(sampleFile, new string('a', 64)), "Different content at the restored path must remain protected.");

            // Verify: 2. PolicyEngine immediately called for the restored file evaluates to Allow and does NOT re-quarantine
            var policyEngine = new PolicyEngine(
                settingsService: new TestSettingsService(),
                toastService: new FakeToastService(),
                auditLogService: new FakeAuditLogService(),
                quarantineService: quarantine,
                protectedPathGuard: new ProtectedPathGuard(),
                reparsePointGuard: new ReparsePointGuard(),
                exclusionService: _exclusionService);

            var finding = new SecurityFinding
            {
                Id = Guid.NewGuid(),
                ObjectName = Path.GetFileName(sampleFile),
                ObjectPath = sampleFile,
                SHA256 = sha256,
                Title = "Backdoor.Trojan",
                RiskScore = 95,
                RiskLevel = RiskLevel.ConfirmedMalicious,
                Category = FindingCategory.KnownMalwareHash,
                Status = FindingStatus.Active
            };

            var enforcementResult = await policyEngine.EnforcePolicyAsync(finding);

            // Policy decision must be Allow because of the restore exclusion
            Assert.Equal(PolicyDecisionAction.Allow, enforcementResult.Action);
            Assert.False(enforcementResult.QuarantinedSuccessfully, "PolicyEngine must NOT auto-quarantine excluded file.");
            Assert.True(File.Exists(sampleFile), "Restored file must remain intact on disk without infinite re-quarantine loop.");
        }

        [Fact]
        public async Task Restore_InvalidatesFileHashMatcherCache()
        {
            // Arrange
            var sampleFile = Path.Combine(_testSandboxDir, "cache_invalidation_sample.exe");
            await File.WriteAllTextAsync(sampleFile, "CACHE_TEST_CONTENT");

            var quarantine = new QuarantineService(
                _hashService,
                customVaultDir: _vaultDir,
                exclusionService: _exclusionService,
                fileHashMatcher: _fileHashMatcher);

            // Seed FileHashMatcher cache for this file
            var fileInfo = new FileInfo(sampleFile);
            _fileHashMatcher.SetCache(sampleFile, fileInfo.Length, fileInfo.LastWriteTimeUtc, new SecurityFinding { Title = "OldThreat" });

            Assert.True(_fileHashMatcher.TryGetCached(sampleFile, fileInfo, false, out _));

            bool quarantined = await quarantine.QuarantineFileAsync(sampleFile, "OldThreat");
            Assert.True(quarantined);

            var items = await quarantine.GetQuarantinedItemsAsync();
            var entry = items[0];

            // Act: Restore file
            bool restored = await quarantine.RestoreFileAsync(entry.Id);
            Assert.True(restored);

            // Re-read file info after restore
            var restoredInfo = new FileInfo(sampleFile);
            // Old cached finding should have been invalidated and not return OldThreat
            _fileHashMatcher.TryGetCached(sampleFile, restoredInfo, false, out var cachedFinding);
            Assert.Null(cachedFinding);
        }
    }
}
