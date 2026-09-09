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
            var alphaCanary = Path.Combine(_testDir, "!_ultron_shield_canary.docx");
            var omegaCanary = Path.Combine(_testDir, "~z_ultron_shield_canary.docx");
            
            Assert.True(File.Exists(alphaCanary), "Alpha canary decoy must exist");
            Assert.True(File.Exists(omegaCanary), "Omega canary decoy must exist");
            Assert.True((File.GetAttributes(alphaCanary) & FileAttributes.Hidden) == FileAttributes.Hidden);
            Assert.True((File.GetAttributes(omegaCanary) & FileAttributes.Hidden) == FileAttributes.Hidden);
            Assert.Equal(2, _engine.CanaryFileCount);
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
            for (int r = 0; r < 10; r++)
            {
                try
                {
                    File.Move(filePath, renamedPath);
                    break;
                }
                catch (IOException) when (r < 9)
                {
                    Thread.Sleep(100);
                }
            }

            for (int i = 0; i < 20 && !alertTriggered; i++)
            {
                Thread.Sleep(100);
            }

            Assert.True(alertTriggered);
        }

        [Fact]
        public async Task Test_PidReuseGuard_DoesNotTerminateNewProcess()
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c ping 127.0.0.1 -n 30 > nul",
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var testProc = System.Diagnostics.Process.Start(psi);
            Assert.NotNull(testProc);
            Assert.False(testProc.HasExited);

            try
            {
                // Artificially pass an incident timestamp from 5 minutes ago
                // The process started just now, so proc.StartTime > incidentTime + 2s (simulating PID reuse)
                var oldIncidentTime = DateTime.UtcNow.AddMinutes(-5);

                var assessment = await _engine.EvaluateAndContainThreatAsync(
                    Path.Combine(_testDir, "suspicious.locked"),
                    "Test PID Reuse Simulation",
                    riskScore: 100,
                    pid: testProc.Id,
                    incidentTimestamp: oldIncidentTime);

                Assert.NotNull(assessment);
                Assert.False(assessment.FilesBlocked == 0 && testProc.HasExited);
                Assert.False(testProc.HasExited, "Process must NOT be terminated when PID-reuse condition is detected!");
            }
            finally
            {
                try { testProc.Kill(); } catch { }
            }
        }

        [Fact]
        public async Task Test_CriticalProcessGuard_NeverTerminatesSystemProcesses()
        {
            // Try to evaluate threat pointing to explorer or system process PID
            var explorerProcs = System.Diagnostics.Process.GetProcessesByName("explorer");
            if (explorerProcs.Length > 0)
            {
                var explorer = explorerProcs[0];
                try
                {
                    var assessment = await _engine.EvaluateAndContainThreatAsync(
                        @"C:\Windows\explorer.exe",
                        "🚨 False Alarm Test on System Explorer",
                        riskScore: 100,
                        pid: explorer.Id);

                    Assert.NotNull(assessment);
                    Assert.False(explorer.HasExited, "Explorer process must NEVER be terminated!");
                }
                finally
                {
                    explorer.Dispose();
                }
            }
        }

        [Fact]
        public async Task Test_MultiCanaryTraps_AlphaAndOmegaTrapsDetected()
        {
            var alphaCanary = Path.Combine(_testDir, "!_ultron_shield_canary.docx");
            var omegaCanary = Path.Combine(_testDir, "~z_ultron_shield_canary.docx");

            var canaryManager = new CanaryTrapManager();
            Assert.True(canaryManager.IsCanaryPath(alphaCanary));
            Assert.True(canaryManager.IsCanaryPath(omegaCanary));

            bool alertTriggered = false;
            _engine.OnRansomwareAttemptDetected += (s, e) =>
            {
                alertTriggered = true;
                Assert.Contains("Canary", e.DetectionReason);
            };

            // Trigger threat on omega canary
            var assessment = await _engine.EvaluateAndContainThreatAsync(
                omegaCanary,
                "🚨 Kritik Tuzak İhlali: Kalkan Canary (yem) dosyası yeniden adlandırıldı veya şifreleniyor!",
                riskScore: 100);

            Assert.NotNull(assessment);
            Assert.True(alertTriggered);
        }

        [Fact]
        public void Test_ScanFilterPolicy_ExcludesCanaryFiles()
        {
            var alphaCanary = @"C:\Users\PC\Documents\!_ultron_shield_canary.docx";
            var omegaCanary = @"C:\Users\PC\Documents\~z_ultron_shield_canary.docx";

            Assert.True(AegisPC.Security.Scanning.ScanFilterPolicy.IsCanaryFile(alphaCanary));
            Assert.True(AegisPC.Security.Scanning.ScanFilterPolicy.IsCanaryFile(omegaCanary));
            Assert.True(AegisPC.Security.Scanning.ScanFilterPolicy.IsSelfOwnedPath(alphaCanary));
            Assert.True(AegisPC.Security.Scanning.ScanFilterPolicy.IsSelfOwnedPath(omegaCanary));
            Assert.False(AegisPC.Security.Scanning.ScanFilterPolicy.IsInspectableCandidate(alphaCanary));
            Assert.False(AegisPC.Security.Scanning.ScanFilterPolicy.IsInspectableCandidate(omegaCanary));
        }

        [Fact]
        public void Test_FileLockProcessResolver_IdentifiesLockingProcess()
        {
            var testLockFile = Path.Combine(_testDir, "restart_mgr_test.dat");
            using (var fs = new FileStream(testLockFile, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                fs.Write(new byte[] { 0x41, 0x45, 0x47, 0x49, 0x53 });
                fs.Flush();

                var lockingPids = FileLockProcessResolver.FindLockingProcessIds(testLockFile);
                Assert.Contains(Environment.ProcessId, lockingPids);
            }
        }
    }
}
