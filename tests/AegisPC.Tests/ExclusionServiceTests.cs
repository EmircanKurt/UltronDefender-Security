using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Policy;
using AegisPC.Contracts.Safety;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Database;
using AegisPC.Security.Detection;
using AegisPC.Security.Policy;
using AegisPC.Security.RealTime;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class ExclusionServiceTests : IDisposable
    {
        private readonly string _testSandboxDir;
        private readonly string _dbPath;
        private readonly DatabaseService _databaseService;
        private readonly FakeAuditLogService _auditLogService;
        private readonly IHashService _hashService;

        public ExclusionServiceTests()
        {
            _testSandboxDir = Path.Combine(Path.GetTempPath(), "ExclusionTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testSandboxDir);

            _dbPath = Path.Combine(_testSandboxDir, "exclusion_test.db");
            _databaseService = new DatabaseService(_dbPath);
            _databaseService.InitializeAsync().GetAwaiter().GetResult();

            _auditLogService = new FakeAuditLogService();
            _hashService = new HashService();
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
            catch (Exception ex)
            {
                Console.WriteLine($"Cleanup error in test: {ex.Message}");
            }
        }

        private ExclusionService CreateExclusionService()
        {
            return new ExclusionService(_databaseService, _auditLogService, null);
        }

        [Fact]
        public async Task Test1_EicarInExcludedDirectory_IsSkippedOrCleanInScan()
        {
            // Arrange
            var exclusionService = CreateExclusionService();
            await exclusionService.InitializeAsync();

            var excludedFolder = Path.Combine(_testSandboxDir, "ExcludedFolder");
            Directory.CreateDirectory(excludedFolder);

            var eicarPath = Path.Combine(excludedFolder, "eicar.com");
            // Standard EICAR string
            await File.WriteAllTextAsync(eicarPath, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            // Add excluded folder
            await exclusionService.AddPathExclusionAsync(excludedFolder, includeSubdirectories: true, reason: "Test 1 exclude folder");

            var allowlist = new AllowlistService(_hashService, null, exclusionService);
            var matcher = new FileHashMatcher(_hashService, new SignatureVerifier(), allowlist, exclusionService: exclusionService);

            // Act: Evaluate hash and allowlist
            var result = await matcher.EvaluateHashAndAllowlistAsync(eicarPath, CancellationToken.None);

            // Assert: Must be skipped/allowlisted before computing hash or running signatures
            Assert.True(result.isAllowlisted);
            Assert.Equal(string.Empty, result.sha256);

            // Also test DetectionHub
            var detectionHub = new DetectionHub(null, null, exclusionService);
            var detResult = await detectionHub.EvaluateAsync(new DetectionContext
            {
                FilePath = eicarPath,
                SHA256 = "TEST_HASH"
            });
            Assert.Equal(DetectionVerdict.Clean, detResult.Verdict);
            Assert.Empty(detResult.Evidences);
        }

        [Fact]
        public async Task Test2_ExcludedFile_IsNeverQuarantinedByPolicyEngine()
        {
            // Arrange
            var exclusionService = CreateExclusionService();
            await exclusionService.InitializeAsync();

            var vaultDir = Path.Combine(_testSandboxDir, "Vault");
            Directory.CreateDirectory(vaultDir);

            var filePath = Path.Combine(_testSandboxDir, "high_risk_tool.exe");
            await File.WriteAllTextAsync(filePath, "Mock High Risk Tool Binary Payload");

            await exclusionService.AddPathExclusionAsync(filePath, includeSubdirectories: false, reason: "Admin allowed tool");

            var quarantineService = new QuarantineService(_hashService, null, null, vaultDir);
            var findingService = new SecurityFindingService();
            var settingsService = new TestSettingsService();
            settingsService.SetSetting("EnableAutoQuarantine", true);
            settingsService.SetSetting("AutoQuarantineThreshold", 85);

            var policyEngine = new PolicyEngine(
                settingsService,
                quarantineService,
                findingService,
                null,
                _auditLogService,
                null,
                new ProtectedPathGuard(),
                new ReparsePointGuard(),
                null,
                null,
                exclusionService);

            var finding = new SecurityFinding
            {
                ObjectPath = filePath,
                ObjectName = Path.GetFileName(filePath),
                RiskScore = 95,
                Category = FindingCategory.KnownMalwareHash,
                RiskLevel = RiskLevel.ConfirmedMalicious,
                Title = "Critical Malicious Match"
            };

            // Act
            var eval = await policyEngine.EnforcePolicyAsync(finding, CancellationToken.None);

            // Assert
            Assert.Equal(PolicyDecisionAction.Allow, eval.Action);
            Assert.False(eval.QuarantinedSuccessfully);
            Assert.True(File.Exists(filePath), "Excluded file must NOT be deleted or quarantined!");
        }

        [Fact]
        public async Task Test3_WhenExclusionIsRemoved_FileIsDetectedAgain()
        {
            // Arrange
            var exclusionService = CreateExclusionService();
            await exclusionService.InitializeAsync();

            var filePath = Path.Combine(_testSandboxDir, "detected_file.exe");
            await File.WriteAllTextAsync(filePath, "Detected File Content");

            var entry = await exclusionService.AddPathExclusionAsync(filePath, includeSubdirectories: false, reason: "Temporary");
            Assert.True(exclusionService.IsExcluded(filePath));

            // Act: Remove exclusion
            var removed = await exclusionService.RemoveExclusionAsync(entry.Id);
            Assert.True(removed);

            // Assert
            Assert.False(exclusionService.IsExcluded(filePath));
        }

        [Fact]
        public async Task Test4_RecursiveFolderExclusion_WorksForDeepSubpaths()
        {
            // Arrange
            var exclusionService = CreateExclusionService();
            await exclusionService.InitializeAsync();

            var rootFolder = Path.Combine(_testSandboxDir, "AppRoot");
            var subFolder = Path.Combine(rootFolder, "Sub1", "Sub2", "Sub3");
            Directory.CreateDirectory(subFolder);

            var deepFile = Path.Combine(subFolder, "deep_tool.dll");
            await File.WriteAllTextAsync(deepFile, "Deep Tool Content");

            // Act: Add root folder with includeSubdirectories = true
            await exclusionService.AddPathExclusionAsync(rootFolder, includeSubdirectories: true, reason: "Recursive root");

            // Assert
            Assert.True(exclusionService.IsExcluded(deepFile));
            Assert.True(exclusionService.IsExcluded(Path.Combine(rootFolder, "Sub1", "another.exe")));

            // If includeSubdirectories = false on another folder:
            var nonRecursiveFolder = Path.Combine(_testSandboxDir, "NonRecursiveRoot");
            var deepFile2 = Path.Combine(nonRecursiveFolder, "ChildDir", "test.dll");
            Directory.CreateDirectory(Path.GetDirectoryName(deepFile2)!);
            await File.WriteAllTextAsync(deepFile2, "Content");

            await exclusionService.AddPathExclusionAsync(nonRecursiveFolder, includeSubdirectories: false, reason: "Non-recursive root");

            // Direct file in folder matches, but child directory file should NOT match
            var directFile = Path.Combine(nonRecursiveFolder, "direct.dll");
            await File.WriteAllTextAsync(directFile, "Direct Content");

            Assert.True(exclusionService.IsExcluded(directFile));
            Assert.False(exclusionService.IsExcluded(deepFile2));
        }

        [Fact]
        public async Task Test5_RootSystemDirectoryExclusion_IsRejected()
        {
            // Arrange
            var exclusionService = CreateExclusionService();
            await exclusionService.InitializeAsync();

            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            {
                await exclusionService.AddPathExclusionAsync(winDir, includeSubdirectories: true);
            });

            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            {
                await exclusionService.AddPathExclusionAsync(@"C:\", includeSubdirectories: true);
            });

            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            {
                await exclusionService.AddPathExclusionAsync(progFiles, includeSubdirectories: true);
            });
        }

        [Fact]
        public async Task Test6_AuditLog_RecordsExclusionAddedAndRemoved()
        {
            // Arrange
            var exclusionService = CreateExclusionService();
            await exclusionService.InitializeAsync();

            var filePath = Path.Combine(_testSandboxDir, "audit_test.exe");
            await File.WriteAllTextAsync(filePath, "Audit test file");

            // Act: Add
            var entry = await exclusionService.AddPathExclusionAsync(filePath, includeSubdirectories: false, reason: "Audit reason");

            // Assert Added AuditLog
            var addedLog = _auditLogService.Entries.FirstOrDefault(e => e.Action == AuditAction.ExclusionAdded);
            Assert.NotNull(addedLog);
            Assert.Equal(filePath, addedLog.TargetPath);

            // Act: Remove
            await exclusionService.RemoveExclusionAsync(entry.Id);

            // Assert Removed AuditLog
            var removedLog = _auditLogService.Entries.FirstOrDefault(e => e.Action == AuditAction.ExclusionRemoved);
            Assert.NotNull(removedLog);
        }
    }
}
