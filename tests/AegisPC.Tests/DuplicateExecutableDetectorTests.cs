using System;
using System.IO;
using AegisPC.Infrastructure.Platform;
using Xunit;

namespace AegisPC.Tests
{
    public class DuplicateExecutableDetectorTests : IDisposable
    {
        private readonly string _testDir;

        public DuplicateExecutableDetectorTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "AegisPC_DupDetector_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testDir))
                {
                    Directory.Delete(_testDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public void CheckForDuplicates_SingleExecutable_ReturnsNoDuplicates()
        {
            var detector = new DuplicateExecutableDetector();
            string subDir = Path.Combine(_testDir, "app");
            Directory.CreateDirectory(subDir);
            string exePath = Path.Combine(subDir, "UltronDefender.exe");
            File.WriteAllText(exePath, "EXE_CONTENT");

            var result = detector.CheckForDuplicates(searchRoot: subDir, currentExePath: exePath);

            Assert.False(result.HasDuplicates);
            Assert.Equal(exePath, result.RecommendedExecutablePath);
        }

        [Fact]
        public void CheckForDuplicates_MultipleExecutables_DetectsAndRecommendsNewerOne()
        {
            var detector = new DuplicateExecutableDetector();

            string dir1 = Path.Combine(_testDir, "OldPublish");
            string dir2 = Path.Combine(_testDir, "NewPublish");
            Directory.CreateDirectory(dir1);
            Directory.CreateDirectory(dir2);

            string oldExe = Path.Combine(dir1, "UltronDefender.exe");
            string newExe = Path.Combine(dir2, "UltronDefender.exe");

            File.WriteAllText(oldExe, "OLD_EXE");
            File.SetLastWriteTimeUtc(oldExe, DateTime.UtcNow.AddDays(-10));

            File.WriteAllText(newExe, "NEW_EXE");
            File.SetLastWriteTimeUtc(newExe, DateTime.UtcNow);

            var result = detector.CheckForDuplicates(searchRoot: _testDir, currentExePath: oldExe);

            Assert.True(result.HasDuplicates);
            Assert.Equal(2, result.DuplicateExecutablePaths.Count);
            Assert.Equal(newExe, result.RecommendedExecutablePath);
            Assert.Contains("güncel olmayabilir", result.AdvisoryMessage);
        }
    }
}
