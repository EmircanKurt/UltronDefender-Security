using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.Service.Update;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class AutoUpdateServiceTests : IDisposable
    {
        private readonly string _testDir;

        public AutoUpdateServiceTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "Aegis_AutoUpdateTests_" + Guid.NewGuid().ToString("N"));
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

        [Fact]
        public async Task ApplyUpdateAsync_CreatesBackupAndReplacesFile()
        {
            var updateService = new AutoUpdateService();

            string appDir = Path.Combine(_testDir, "app");
            Directory.CreateDirectory(appDir);

            string targetFile = Path.Combine(appDir, "service_binary.dll");
            await File.WriteAllTextAsync(targetFile, "VERSION_1_ORIGINAL");

            string stagingFile = Path.Combine(_testDir, "service_binary.dll");
            await File.WriteAllTextAsync(stagingFile, "VERSION_2_UPDATED");

            bool applied = await updateService.ApplyUpdateAsync(stagingFile, appDir);

            Assert.True(applied);
            string updatedContent = await File.ReadAllTextAsync(targetFile);
            Assert.Equal("VERSION_2_UPDATED", updatedContent);

            // Rollback backup should exist
            string backupFile = Path.Combine(AutoUpdateService.BackupDirectory, "service_binary.dll.bak");
            Assert.True(File.Exists(backupFile));
            string backupContent = await File.ReadAllTextAsync(backupFile);
            Assert.Equal("VERSION_1_ORIGINAL", backupContent);
        }

        [Fact]
        public async Task RollbackUpdateAsync_RestoresOriginalFilesFromBackup()
        {
            var updateService = new AutoUpdateService();

            string appDir = Path.Combine(_testDir, "app_rollback");
            Directory.CreateDirectory(appDir);
            Directory.CreateDirectory(AutoUpdateService.BackupDirectory);

            string targetFile = Path.Combine(appDir, "engine.dll");
            await File.WriteAllTextAsync(targetFile, "VERSION_FAILED_UPDATE");

            string backupFile = Path.Combine(AutoUpdateService.BackupDirectory, "engine.dll.bak");
            await File.WriteAllTextAsync(backupFile, "VERSION_ORIGINAL_BACKUP");

            bool restored = await updateService.RollbackUpdateAsync(appDir);

            Assert.True(restored);
            string restoredContent = await File.ReadAllTextAsync(targetFile);
            Assert.Equal("VERSION_ORIGINAL_BACKUP", restoredContent);
        }

        [Fact]
        public void ComputeSha256_ValidatesIntegrityAccurately()
        {
            string sampleFile = Path.Combine(_testDir, "test_hash.txt");
            File.WriteAllText(sampleFile, "AegisPC Secure Update Test");

            using var sha = SHA256.Create();
            byte[] expectedBytes = sha.ComputeHash(Encoding.UTF8.GetBytes("AegisPC Secure Update Test"));
            string expectedHex = Convert.ToHexString(expectedBytes).ToLowerInvariant();

            using var stream = File.OpenRead(sampleFile);
            byte[] actualBytes = sha.ComputeHash(stream);
            string actualHex = Convert.ToHexString(actualBytes).ToLowerInvariant();

            Assert.Equal(expectedHex, actualHex);
        }
    }
}
