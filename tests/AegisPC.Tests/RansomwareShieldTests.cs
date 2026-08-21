using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class RansomwareShieldTests : IDisposable
    {
        private readonly string _testDir;
        private readonly RansomwareProtectionEngine _engine;

        public RansomwareShieldTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "AegisRansomwareTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);

            _engine = new RansomwareProtectionEngine(null);
            // Clear defaults and add our test dir
            foreach (var dir in _engine.ProtectedDirectories)
            {
                _engine.RemoveProtectedDirectory(dir);
            }
            _engine.AddProtectedDirectory(_testDir);
        }

        public void Dispose()
        {
            _engine.StopShield();
            if (Directory.Exists(_testDir))
            {
                try { Directory.Delete(_testDir, true); } catch { }
            }
        }

        [Fact]
        public void Test_CanaryFileCreation_WhenShieldStarted()
        {
            _engine.StartShield();
            var canaryPath = Path.Combine(_testDir, "!_ultron_shield_canary.docx");
            
            Assert.True(File.Exists(canaryPath));
            Assert.True((File.GetAttributes(canaryPath) & FileAttributes.Hidden) == FileAttributes.Hidden);
            Assert.Equal(1, _engine.CanaryFileCount);
        }

        [Fact]
        public void Test_CanaryFileModification_TriggersAlert()
        {
            bool alertTriggered = false;
            _engine.OnRansomwareAttemptDetected += (s, e) => 
            {
                alertTriggered = true;
                Assert.Contains("Canary", e.DetectionReason);
            };

            _engine.StartShield();
            var canaryPath = Path.Combine(_testDir, "!_ultron_shield_canary.docx");
            
            // Unhide and modify to trigger event
            File.SetAttributes(canaryPath, FileAttributes.Normal);
            File.AppendAllText(canaryPath, "modified");

            // Wait for FileSystemWatcher to fire with robust polling
            for (int i = 0; i < 20 && !alertTriggered; i++)
            {
                Thread.Sleep(100);
            }

            Assert.True(alertTriggered);
        }

        [Fact]
        public void Test_EntropyBurstDetection()
        {
            bool alertTriggered = false;
            _engine.OnRansomwareAttemptDetected += (s, e) => 
            {
                alertTriggered = true;
                Assert.Contains("Anormal dosya değişim sıklığı", e.DetectionReason);
            };

            _engine.StartShield();

            // Create >18 files rapidly
            for (int i = 0; i < 20; i++)
            {
                var filePath = Path.Combine(_testDir, $"testfile_{i}.txt");
                File.WriteAllText(filePath, "test content");
            }

            for (int i = 0; i < 20 && !alertTriggered; i++)
            {
                Thread.Sleep(100);
            }

            Assert.True(alertTriggered);
        }

        [Fact]
        public void Test_KnownRansomwareExtension_TriggersAlert()
        {
            bool alertTriggered = false;
            _engine.OnRansomwareAttemptDetected += (s, e) => 
            {
                alertTriggered = true;
                Assert.Contains("fidye", e.DetectionReason, StringComparison.OrdinalIgnoreCase);
            };

            _engine.StartShield();

            var filePath = Path.Combine(_testDir, "test.txt");
            File.WriteAllText(filePath, "content");
            Thread.Sleep(100);

            var renamedPath = Path.Combine(_testDir, "test.encrypted");
            File.Move(filePath, renamedPath);

            for (int i = 0; i < 20 && !alertTriggered; i++)
            {
                Thread.Sleep(100);
            }

            Assert.True(alertTriggered);
        }
    }
}
