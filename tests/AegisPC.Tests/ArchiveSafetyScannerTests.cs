using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class ArchiveSafetyScannerTests
    {
        [Fact]
        public async Task ScanArchiveAsync_NormalZip_ReturnsClean()
        {
            var scanner = new ArchiveSafetyScanner();
            var zipPath = Path.Combine(Path.GetTempPath(), $"clean_archive_{Guid.NewGuid():N}.zip");

            try
            {
                using (var fs = new FileStream(zipPath, FileMode.Create))
                using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    var entry = zip.CreateEntry("document.txt");
                    using var writer = new StreamWriter(entry.Open());
                    writer.WriteLine("Normal text content");
                }

                var result = await scanner.ScanArchiveAsync(zipPath);
                Assert.True(result.IsArchive);
                Assert.False(result.IsZipBomb);
                Assert.Equal(1, result.TotalEntries);
                Assert.Empty(result.Findings);
            }
            finally
            {
                try { if (File.Exists(zipPath)) File.Delete(zipPath); } catch { }
            }
        }

        [Fact]
        public async Task ScanArchiveAsync_EmbeddedMalware_FlagsFinding()
        {
            var scanner = new ArchiveSafetyScanner();
            var zipPath = Path.Combine(Path.GetTempPath(), $"infected_archive_{Guid.NewGuid():N}.zip");
            var eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

            try
            {
                using (var fs = new FileStream(zipPath, FileMode.Create))
                using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    var entry = zip.CreateEntry("eicar.com");
                    using var writer = new StreamWriter(entry.Open());
                    writer.Write(eicarString);
                }

                var result = await scanner.ScanArchiveAsync(zipPath);
                Assert.True(result.IsArchive);
                Assert.NotEmpty(result.Findings);
                Assert.Contains("EICAR", result.Findings[0].Title);
            }
            finally
            {
                try { if (File.Exists(zipPath)) File.Delete(zipPath); } catch { }
            }
        }
    }

    public class MalwareSignatureDatabaseTests
    {
        [Fact]
        public void CheckHash_EicarSha256_ReturnsThreatMatch()
        {
            var eicarHash = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";
            var match = MalwareSignatureDatabase.CheckHash(eicarHash);

            Assert.True(match.IsMatched);
            Assert.Equal(100, match.SeverityScore);
            Assert.Contains("EICAR", match.ThreatName);
        }

        [Fact]
        public void CheckHash_UnknownCleanHash_ReturnsNoMatch()
        {
            var cleanHash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
            var match = MalwareSignatureDatabase.CheckHash(cleanHash);

            Assert.False(match.IsMatched);
        }
    }
}
