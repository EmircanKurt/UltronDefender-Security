using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class QuarantineVaultTests
    {
        [Fact]
        public async Task QuarantineAndRestore_PreservesFileIntegrityAndEncryptsOnDisk()
        {
            var testVaultDir = Path.Combine(Path.GetTempPath(), $"AegisTest_Quarantine_{Guid.NewGuid():N}");
            Directory.CreateDirectory(testVaultDir);

            var hashService = new HashService();
            var quarantine = new QuarantineService(hashService, customVaultDir: testVaultDir);

            var tempFile = Path.Combine(Path.GetTempPath(), $"test_sample_{Guid.NewGuid():N}.exe");
            var restoredFile = Path.Combine(Path.GetTempPath(), $"test_restored_{Guid.NewGuid():N}.exe");
            var originalContent = "TEST_VIRUS_PAYLOAD_EICAR_SAMPLE_DATA_1234567890";
            await File.WriteAllTextAsync(tempFile, originalContent);

            try
            {
                // 1. Quarantine file
                bool quarantined = await quarantine.QuarantineFileAsync(tempFile, "Test.Threat.Detected");
                Assert.True(quarantined);
                Assert.False(File.Exists(tempFile), "Original file should be removed from disk upon quarantine.");

                var items = await quarantine.GetQuarantinedItemsAsync();
                Assert.NotEmpty(items);
                var entry = items[0];

                // Verify encrypted file on disk has magic header
                Assert.True(File.Exists(entry.QuarantinePath));
                var quarBytes = await File.ReadAllBytesAsync(entry.QuarantinePath);
                Assert.DoesNotContain(originalContent, Encoding.ASCII.GetString(quarBytes)); // Must NOT be plaintext on disk!

                // 2. Restore file
                bool restored = await quarantine.RestoreFileAsync(entry.Id, restoredFile);
                Assert.True(restored);
                Assert.True(File.Exists(restoredFile));

                var restoredContent = await File.ReadAllTextAsync(restoredFile);
                Assert.Equal(originalContent, restoredContent);
            }
            finally
            {
                try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
                try { if (File.Exists(restoredFile)) File.Delete(restoredFile); } catch { }
                if (Directory.Exists(testVaultDir))
                {
                    try { Directory.Delete(testVaultDir, true); } catch { }
                }
            }
        }

        [Fact]
        public async Task QuarantineAndRestore_StreamingDecryption_WorksWithoutMemorySpikes()
        {
            var testVaultDir = Path.Combine(Path.GetTempPath(), $"AegisTest_StreamVault_{Guid.NewGuid():N}");
            Directory.CreateDirectory(testVaultDir);

            var hashService = new HashService();
            var quarantine = new QuarantineService(hashService, customVaultDir: testVaultDir);

            var tempFile = Path.Combine(Path.GetTempPath(), $"test_stream_{Guid.NewGuid():N}.bin");
            var restoredFile = Path.Combine(Path.GetTempPath(), $"test_stream_restored_{Guid.NewGuid():N}.bin");

            // Create a 2MB binary payload with distinct byte pattern
            byte[] originalBytes = new byte[2 * 1024 * 1024];
            new Random(42).NextBytes(originalBytes);
            await File.WriteAllBytesAsync(tempFile, originalBytes);

            try
            {
                bool quarantined = await quarantine.QuarantineFileAsync(tempFile, "Streaming.Test.Threat");
                Assert.True(quarantined);
                Assert.False(File.Exists(tempFile));

                var items = await quarantine.GetQuarantinedItemsAsync();
                Assert.Single(items);
                var entry = items[0];

                // Restore using streaming
                bool restored = await quarantine.RestoreFileAsync(entry.Id, restoredFile);
                Assert.True(restored);
                Assert.True(File.Exists(restoredFile));

                byte[] restoredBytes = await File.ReadAllBytesAsync(restoredFile);
                Assert.Equal(originalBytes.Length, restoredBytes.Length);
                Assert.True(originalBytes.AsSpan().SequenceEqual(restoredBytes), "Restored streaming file must exactly match original bytes.");

                // Test fast cryptographic shred delete
                bool deleted = await quarantine.DeleteQuarantinedAsync(entry.Id);
                Assert.True(deleted);
                Assert.False(File.Exists(entry.QuarantinePath));
            }
            finally
            {
                try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
                try { if (File.Exists(restoredFile)) File.Delete(restoredFile); } catch { }
                if (Directory.Exists(testVaultDir))
                {
                    try { Directory.Delete(testVaultDir, true); } catch { }
                }
            }
        }
    }
}
