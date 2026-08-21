using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Archive;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Archive;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class SecureArchiveTests : IDisposable
    {
        private readonly string _sandboxDir;

        public SecureArchiveTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "Aegis_ArchiveTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Test_SecureArchive_DetectsNormalZipArchive()
        {
            var engine = new SecureArchiveEngine();
            var zipPath = Path.Combine(_sandboxDir, "normal.zip");

            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("document.txt");
                using var writer = new StreamWriter(entry.Open());
                writer.WriteLine("Hello, this is normal documentation.");
            }

            var verdict = await engine.InspectArchiveAsync(zipPath);

            Assert.True(verdict.IsValidArchive);
            Assert.False(verdict.HasZipBomb);
            Assert.False(verdict.IsDepthExceeded);
            Assert.Equal(1, verdict.TotalEntryCount);
            Assert.Empty(verdict.SuspiciousFileNames);
        }

        [Fact]
        public async Task Test_SecureArchive_DetectsEmbeddedExecutables()
        {
            var engine = new SecureArchiveEngine();
            var zipPath = Path.Combine(_sandboxDir, "trojan_inside.zip");

            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("invoice.pdf.exe");
                using var writer = new StreamWriter(entry.Open());
                writer.WriteLine("MZ_DUMMY_EXE");
            }

            var verdict = await engine.InspectArchiveAsync(zipPath);

            Assert.True(verdict.IsValidArchive);
            Assert.Contains(verdict.SuspiciousFileNames, f => f.Contains("invoice.pdf.exe"));
            Assert.Contains(verdict.Evidences, e => e.RuleName == "ARCHIVE_EMBEDDED_EXECUTABLE_PAYLOAD");
        }

        [Fact]
        public async Task Test_SecureArchive_DetectsZipBombCompressionRatio()
        {
            var engine = new SecureArchiveEngine();
            var zipPath = Path.Combine(_sandboxDir, "zipbomb_ratio.zip");

            // Create highly compressible file (2 MB of repeating zeros)
            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("huge_zeros.bin", CompressionLevel.Optimal);
                using var stream = entry.Open();
                var zeros = new byte[64 * 1024];
                for (int i = 0; i < 32; i++) // 2 MB
                {
                    stream.Write(zeros, 0, zeros.Length);
                }
            }

            var limits = new ArchiveSafetyLimits { MaxCompressionRatio = 50.0 };
            var verdict = await engine.InspectArchiveAsync(zipPath, limits);

            Assert.True(verdict.IsValidArchive);
            Assert.True(verdict.HasZipBomb);
            Assert.True(verdict.HighestCompressionRatio > 50.0);
            Assert.Contains(verdict.Evidences, e => e.RuleName == "ARCHIVE_ZIP_BOMB_RATIO_EXCEEDED");
        }

        [Fact]
        public async Task Test_SecureArchive_DetectsTotalUncompressedSizeQuota()
        {
            var engine = new SecureArchiveEngine();
            var zipPath = Path.Combine(_sandboxDir, "quota_test.zip");

            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                for (int i = 0; i < 5; i++)
                {
                    var entry = zip.CreateEntry($"data_{i}.dat");
                    using var writer = new StreamWriter(entry.Open());
                    writer.Write(new string('A', 1024 * 1024)); // 1 MB each
                }
            }

            var limits = new ArchiveSafetyLimits { MaxTotalUncompressedBytes = 2 * 1024 * 1024 }; // 2 MB limit
            var verdict = await engine.InspectArchiveAsync(zipPath, limits);

            Assert.True(verdict.IsValidArchive);
            Assert.True(verdict.IsQuotaExceeded);
            Assert.Contains(verdict.Evidences, e => e.RuleName == "ARCHIVE_TOTAL_SIZE_QUOTA_EXCEEDED");
        }

        [Fact]
        public async Task Test_SecureArchive_DetectsNestedArchiveDepth()
        {
            var engine = new SecureArchiveEngine();
            var innerZip1 = Path.Combine(_sandboxDir, "inner1.zip");
            var innerZip2 = Path.Combine(_sandboxDir, "inner2.zip");
            var outerZip = Path.Combine(_sandboxDir, "outer.zip");

            // Level 3: inner2.zip contains a text file
            using (var zip = ZipFile.Open(innerZip2, ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("payload.txt");
                using var writer = new StreamWriter(entry.Open());
                writer.WriteLine("Nested payload");
            }

            // Level 2: inner1.zip contains inner2.zip
            using (var zip = ZipFile.Open(innerZip1, ZipArchiveMode.Create))
            {
                zip.CreateEntryFromFile(innerZip2, "inner2.zip");
            }

            // Level 1: outer.zip contains inner1.zip
            using (var zip = ZipFile.Open(outerZip, ZipArchiveMode.Create))
            {
                zip.CreateEntryFromFile(innerZip1, "inner1.zip");
            }

            var limits = new ArchiveSafetyLimits { MaxNestedDepth = 2 };
            var verdict = await engine.InspectArchiveAsync(outerZip, limits);

            Assert.True(verdict.IsValidArchive);
            Assert.True(verdict.DeepestLevel >= 3);
            Assert.True(verdict.IsDepthExceeded);
            Assert.Contains(verdict.Evidences, e => e.RuleName == "ARCHIVE_NESTED_DEPTH_EXCEEDED");
        }

        [Fact]
        public async Task Test_SecureArchive_DetectorPlugin_EmitsArchiveAnomalyEvidences()
        {
            var plugin = new ArchiveDetectorPlugin();
            var zipPath = Path.Combine(_sandboxDir, "plugin_test.zip");

            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("danger.scr");
                using var writer = new StreamWriter(entry.Open());
                writer.WriteLine("MZ_TEST");
            }

            var context = new DetectionContext { FilePath = zipPath };
            var evidences = await plugin.EvaluateAsync(context);

            Assert.NotEmpty(evidences);
            Assert.Contains(evidences, e => e.RuleName == "ARCHIVE_EMBEDDED_EXECUTABLE_PAYLOAD");
        }
    }
}
