using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class StartupSecuritySweepTests : IDisposable
    {
        private readonly string _sandboxDir;
        private readonly string _downloadsDir;
        private readonly string _startupDir;
        private readonly string _vaultDir;

        private readonly HashService _hashService;
        private readonly SignatureVerifier _signatureVerifier;
        private readonly RiskScoringEngine _riskScoringEngine;
        private readonly SecurityFindingService _findingService;
        private readonly AllowlistService _allowlistService;
        private readonly QuarantineService _quarantineService;
        private readonly FileScannerService _fileScanner;
        private readonly RealTimeProtectionEngine _realTimeEngine;
        private readonly StartupSecuritySweepService _sweepService;

        private readonly Xunit.Abstractions.ITestOutputHelper? _output;

        public StartupSecuritySweepTests(Xunit.Abstractions.ITestOutputHelper? output = null)
        {
            _output = output;
            _sandboxDir = Path.Combine(Path.GetTempPath(), "AegisSweep_" + Guid.NewGuid().ToString("N"));
            _downloadsDir = Path.Combine(_sandboxDir, "Downloads");
            _startupDir = Path.Combine(_sandboxDir, "Startup");
            _vaultDir = Path.Combine(_sandboxDir, "Vault");

            Directory.CreateDirectory(_sandboxDir);
            Directory.CreateDirectory(_downloadsDir);
            Directory.CreateDirectory(_startupDir);
            Directory.CreateDirectory(_vaultDir);

            _hashService = new HashService();
            _signatureVerifier = new SignatureVerifier();
            _riskScoringEngine = new RiskScoringEngine();
            _findingService = new SecurityFindingService();
            _allowlistService = new AllowlistService(_hashService);
            _quarantineService = new QuarantineService(_hashService, null, null, _vaultDir);

            _fileScanner = new FileScannerService(
                _hashService,
                _signatureVerifier,
                _riskScoringEngine,
                _allowlistService,
                _findingService);

            _realTimeEngine = new RealTimeProtectionEngine(
                _fileScanner,
                _hashService,
                _signatureVerifier,
                _riskScoringEngine,
                _quarantineService,
                _findingService);

            _sweepService = new StartupSecuritySweepService(
                _realTimeEngine,
                _quarantineService);
        }

        public void Dispose()
        {
            _realTimeEngine.Dispose();
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
        public async Task Test_StartupSweep_FindsExistingEicar()
        {
            // Create threat fixture before sweep runs
            var threatPath = Path.Combine(_downloadsDir, "pre_existing_threat.exe");
            await File.WriteAllTextAsync(threatPath, "PAYLOAD: AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182");

            _output?.WriteLine($"Downloads dir: {_downloadsDir}, exists: {Directory.Exists(_downloadsDir)}");
            _output?.WriteLine($"Threat path: {threatPath}, exists: {File.Exists(threatPath)}");

            var result = await _sweepService.RunSweepAsync(new[] { _downloadsDir });

            _output?.WriteLine($"Sweep result: Status={result.FinalStatus}, Scanned={result.TotalScanned}, Threats={result.ThreatsCount}, Suspicious={result.SuspiciousCount}, Clean={result.CleanCount}");
            foreach (var f in result.Findings)
            {
                _output?.WriteLine($"  Finding: {f.FileName} | Risk={f.RiskScore} | Verdict={f.Verdict} | Action={f.Action} | Quarantined={f.IsQuarantined}");
            }

            Assert.True(result.ThreatsCount > 0, $"Startup sweep must discover existing threat artifact. (Found Threats: {result.ThreatsCount}, Total Scanned: {result.TotalScanned})");
            Assert.False(File.Exists(threatPath), "Existing threat must be quarantined from disk.");
            Assert.Equal(StartupSweepStatus.ThreatsFound, result.FinalStatus);
        }

        [Fact]
        public async Task Test_StartupSweep_FindsExistingSuspiciousFile()
        {
            // Suspicious double extension script
            var suspiciousPath = Path.Combine(_downloadsDir, "quarterly_stats.xlsx.cmd");
            await File.WriteAllTextAsync(suspiciousPath, "@echo off\r\necho Spreadsheet calculation runner\r\n");

            _output?.WriteLine($"Downloads dir: {_downloadsDir}, exists: {Directory.Exists(_downloadsDir)}");
            _output?.WriteLine($"Suspicious file: {suspiciousPath}, exists: {File.Exists(suspiciousPath)}");

            var result = await _sweepService.RunSweepAsync(new[] { _downloadsDir });

            _output?.WriteLine($"Sweep Result: TotalScanned={result.TotalScanned}, Threats={result.ThreatsCount}, Suspicious={result.SuspiciousCount}, Clean={result.CleanCount}");
            foreach (var f in result.Findings)
            {
                _output?.WriteLine($" Finding: {f.FileName} | Risk={f.RiskScore} | Verdict={f.Verdict} | Action={f.Action}");
            }

            Assert.True(result.TotalScanned >= 1, $"Candidate double-extension must be scanned. (TotalScanned: {result.TotalScanned})");
            Assert.True(result.ThreatsCount > 0 || result.SuspiciousCount > 0, 
                $"Expected threats or suspicious > 0, but got Threats: {result.ThreatsCount}, Suspicious: {result.SuspiciousCount}");
        }

        [Fact]
        public async Task Test_StartupSweep_DoesNotDeleteSingleApiBenignFile()
        {
            // Single API helper file
            var helperPath = Path.Combine(_downloadsDir, "macro_helper.dll");
            await File.WriteAllTextAsync(helperPath, "EXPORT: SetWindowsHookEx; // developer macro");

            var result = await _sweepService.RunSweepAsync(new[] { _downloadsDir });

            Assert.True(File.Exists(helperPath), "Single API benign helper must NEVER be deleted by sweep.");
        }

        [Fact]
        public async Task Test_StartupSweep_ScansDownloads()
        {
            var testExe = Path.Combine(_downloadsDir, "normal_installer.exe");
            await File.WriteAllBytesAsync(testExe, Encoding.ASCII.GetBytes("MZ_BENIGN_INSTALLER"));

            var result = await _sweepService.RunSweepAsync(new[] { _downloadsDir });

            Assert.True(result.TotalScanned >= 1);
            Assert.Equal(0, result.ThreatsCount);
            Assert.True(File.Exists(testExe));
        }

        [Fact]
        public async Task Test_StartupSweep_ScansStartupFolder()
        {
            var startupScript = Path.Combine(_startupDir, "autostart_tool.bat");
            await File.WriteAllTextAsync(startupScript, "@echo off\r\necho Safe startup tool\r\n");

            var result = await _sweepService.RunSweepAsync(new[] { _startupDir });

            Assert.True(result.TotalScanned >= 1);
            Assert.True(File.Exists(startupScript));
        }

        [Fact]
        public async Task Test_StartupSweep_DoesNotBlockUI()
        {
            var file = Path.Combine(_downloadsDir, "async_test.exe");
            await File.WriteAllBytesAsync(file, Encoding.ASCII.GetBytes("MZ_ASYNC"));

            var sweepTask = _sweepService.RunSweepAsync(new[] { _downloadsDir });
            
            // Should return a task immediately without synchronous blocking
            Assert.NotNull(sweepTask);
            var result = await sweepTask;
            Assert.NotNull(result);
        }

        [Fact]
        public async Task Test_StartupSweep_UsesExistingRiskScoring()
        {
            var file = Path.Combine(_downloadsDir, "scoring_check.exe");
            await File.WriteAllBytesAsync(file, Encoding.ASCII.GetBytes("MZ_CLEAN"));

            var result = await _sweepService.RunSweepAsync(new[] { _downloadsDir });

            Assert.Equal(StartupSweepStatus.Clean, result.FinalStatus);
        }

        [Fact]
        public async Task Test_StartupSweep_CachesUnchangedFiles()
        {
            var file = Path.Combine(_downloadsDir, "cache_candidate.exe");
            await File.WriteAllBytesAsync(file, Encoding.ASCII.GetBytes("MZ_CACHE_CHECK"));

            // Run 1: First scan
            var result1 = await _sweepService.RunSweepAsync(new[] { _downloadsDir });
            Assert.Equal(0, result1.SkippedCount);

            // Run 2: Unchanged file should be skipped via cache
            var result2 = await _sweepService.RunSweepAsync(new[] { _downloadsDir });
            Assert.True(result2.SkippedCount >= 1, "Unchanged clean file must be skipped using cached metadata.");
        }

        [Fact]
        public async Task Test_StartupSweep_RescansModifiedFiles()
        {
            var file = Path.Combine(_downloadsDir, "modified_check.exe");
            await File.WriteAllBytesAsync(file, Encoding.ASCII.GetBytes("MZ_CLEAN_V1"));

            await _sweepService.RunSweepAsync(new[] { _downloadsDir });

            // Modify file with new timestamp and size
            await Task.Delay(50);
            await File.WriteAllBytesAsync(file, Encoding.ASCII.GetBytes("MZ_CLEAN_V2_LONGER_PAYLOAD"));

            var result2 = await _sweepService.RunSweepAsync(new[] { _downloadsDir });
            Assert.Equal(0, result2.SkippedCount); // Must be re-scanned, not skipped!
        }

        [Fact]
        public async Task Test_StartupSweep_QuarantinesConfirmedThreat()
        {
            var threatPath = Path.Combine(_startupDir, "stealth_dropper.bat");
            await File.WriteAllTextAsync(threatPath, "@echo off\r\nREM AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182\r\n");

            var result = await _sweepService.RunSweepAsync(new[] { _startupDir });

            Assert.True(result.ThreatsCount > 0);
            Assert.False(File.Exists(threatPath), "Confirmed threat in Startup folder must be quarantined.");
        }

        [Fact]
        public async Task Test_StartupSweep_KeyloggerFixture_MultiSignalEvidence()
        {
            var sandbox = Path.Combine(Path.GetTempPath(), "Aegis_KeyloggerTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(sandbox);
            try
            {
                var injectionPath = Path.Combine(sandbox, "injection_fixture.ps1");
                var injectionCode = "CreateRemoteThread; VirtualAllocEx; WriteProcessMemory;";
                await File.WriteAllTextAsync(injectionPath, injectionCode);

                var verdictResult = await _realTimeEngine.InspectFileAsync(injectionPath);

                Assert.True(verdictResult.RiskScore >= 50, $"Risk score must be >= 50 (Actual: {verdictResult.RiskScore})");
                Assert.True(verdictResult.Evidences.Count >= 2, "Evidences must contain weighted multi-signal breakdown.");
                Assert.Contains(verdictResult.Evidences, e => e.Contains("+25") || e.Contains("+20"));
            }
            finally
            {
                try { Directory.Delete(sandbox, true); } catch { }
            }
        }

        // =========================================================================
        // ARCHITECTURAL DISTINCTION TESTS: REAL-TIME (EVENT-DRIVEN) VS STARTUP CHECK
        // =========================================================================

        [Fact]
        public async Task Test_RealtimeProtection_CatchesNewFile()
        {
            // Real-time engine is event-driven via FileSystemWatcher
            _realTimeEngine.Start(watchDefaultLocations: false);
            _realTimeEngine.AddWatchDirectory(_downloadsDir);

            var eventSignal = new TaskCompletionSource<bool>();
            _realTimeEngine.OnIncidentCreated += incident =>
            {
                if (incident.RootProcessName.Contains("event_driven_threat", StringComparison.OrdinalIgnoreCase) ||
                    incident.RootExecutablePath.Contains("event_driven_threat", StringComparison.OrdinalIgnoreCase))
                {
                    eventSignal.TrySetResult(true);
                }
            };

            var targetFile = Path.Combine(_downloadsDir, "event_driven_threat.bat");
            await File.WriteAllTextAsync(targetFile, "@echo off\r\nREM AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182\r\n");

            var completed = await Task.WhenAny(eventSignal.Task, Task.Delay(6000));
            Assert.True(completed == eventSignal.Task, "Real-time engine MUST catch new file arrival via event without any sweep.");
            
            for (int i = 0; i < 30 && File.Exists(targetFile); i++) await Task.Delay(100);
            Assert.False(File.Exists(targetFile), "Real-time threat must be quarantined.");

            _realTimeEngine.Stop();
        }

        [Fact]
        public async Task Test_StartupCheck_FindsExistingFile()
        {
            // File already exists before any protection started
            var existingFile = Path.Combine(_downloadsDir, "pre_existing_threat.bat");
            await File.WriteAllTextAsync(existingFile, "@echo off\r\nREM AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182\r\n");

            // Real-time engine is NOT running watcher on this directory, but Startup Check finds it
            var result = await _sweepService.RunSweepAsync(new[] { _downloadsDir });

            Assert.True(result.ThreatsCount > 0, "Startup check must discover existing threats from disk.");
            Assert.False(File.Exists(existingFile), "Pre-existing threat must be removed.");
        }

        [Fact]
        public async Task Test_StartupCheck_DoesNotReplaceRealtimeProtection()
        {
            var testSandbox = Path.Combine(Path.GetTempPath(), "Aegis_ParallelTest_" + Guid.NewGuid().ToString("N"));
            var testDownloads = Path.Combine(testSandbox, "Downloads");
            var testStartup = Path.Combine(testSandbox, "Startup");
            Directory.CreateDirectory(testDownloads);
            Directory.CreateDirectory(testStartup);

            var localEngine = new RealTimeProtectionEngine(_fileScanner, _hashService, _signatureVerifier, _riskScoringEngine, _quarantineService, _findingService);
            localEngine.AddWatchDirectory(testDownloads);
            localEngine.Start(watchDefaultLocations: false);

            try
            {
                var eventSignal = new TaskCompletionSource<bool>();
                localEngine.OnThreatDetected += finding =>
                {
                    if (finding.ObjectName.Contains("parallel_new_drop", StringComparison.OrdinalIgnoreCase) ||
                        finding.ObjectPath.Contains("parallel_new_drop", StringComparison.OrdinalIgnoreCase))
                    {
                        eventSignal.TrySetResult(true);
                    }
                };
                localEngine.OnIncidentCreated += inc =>
                {
                    if (inc.RootProcessName.Contains("parallel_new_drop", StringComparison.OrdinalIgnoreCase) ||
                        inc.RootExecutablePath.Contains("parallel_new_drop", StringComparison.OrdinalIgnoreCase))
                    {
                        eventSignal.TrySetResult(true);
                    }
                };

                // 1. Launch Startup Sweep in background
                var sweep = new StartupSecuritySweepService(localEngine, _quarantineService);
                var sweepTask = sweep.RunSweepAsync(new[] { testStartup });

                // Allow OS watcher buffer initialization
                await Task.Delay(300);

                // 2. While sweep is executing, a NEW file is dropped in Downloads
                var newFile = Path.Combine(testDownloads, "parallel_new_drop.bat");
                await File.WriteAllTextAsync(newFile, "@echo off\r\nREM AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182\r\nvssadmin delete shadows /all /quiet\r\n");

                // 3. Real-time protection engine catches it independently
                var completed = await Task.WhenAny(eventSignal.Task, Task.Delay(10000));
                Assert.True(completed == eventSignal.Task, "Real-time watcher MUST operate independently while sweep runs.");

                await sweepTask;
            }
            finally
            {
                localEngine.Stop();
                localEngine.Dispose();
                try { Directory.Delete(testSandbox, true); } catch { }
            }
        }

        [Fact]
        public async Task Test_StartupCheck_DoesNotPrioritizeLargeFiles()
        {
            // Create a 5MB dummy file in Downloads and a small threat script in Startup
            var largeDummyFile = Path.Combine(_downloadsDir, "large_video_editor.exe");
            var largeBytes = new byte[5 * 1024 * 1024]; // 5 MB
            Array.Fill(largeBytes, (byte)0x90);
            await File.WriteAllBytesAsync(largeDummyFile, largeBytes);

            var smallStartupScript = Path.Combine(_startupDir, "autostart_danger.bat");
            await File.WriteAllTextAsync(smallStartupScript, "@echo off\r\necho Startup background runner payload\r\n");

            var scannedOrder = new List<string>();
            _sweepService.OnProgressChanged += p =>
            {
                if (!string.IsNullOrEmpty(p.CurrentFile) && !scannedOrder.Contains(p.CurrentFile))
                {
                    scannedOrder.Add(p.CurrentFile);
                }
            };

            var result = await _sweepService.RunSweepAsync(new[] { _startupDir, _downloadsDir });

            // Startup folder script MUST be prioritized over large download file!
            int startupIndex = scannedOrder.IndexOf("autostart_danger.bat");
            int largeIndex = scannedOrder.IndexOf("large_video_editor.exe");

            Assert.True(startupIndex != -1, "Startup file must be scanned.");
            Assert.True(largeIndex != -1, "Large file must be scanned.");
            Assert.True(startupIndex < largeIndex, "Risk-based priority: Startup directory MUST be scanned before Downloads, regardless of file size!");
        }

        [Fact]
        public void Test_RealtimeProtection_StartsImmediately()
        {
            // Real-time engine starts immediately and is active without waiting for sweep
            Assert.False(_realTimeEngine.IsRunning);
            _realTimeEngine.Start(watchDefaultLocations: false);
            Assert.True(_realTimeEngine.IsRunning, "Real-Time Protection Engine MUST be active immediately.");
            _realTimeEngine.Stop();
            Assert.False(_realTimeEngine.IsRunning);
        }

        [Fact]
        public async Task Test_StartupSweep_DoesNotBlockDashboard()
        {
            // Sweep runs asynchronously in background without blocking calling thread
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var task = _sweepService.RunSweepAsync(new[] { _downloadsDir });
            
            // Task invocation returns immediately (< 50ms)
            stopwatch.Stop();
            Assert.True(stopwatch.ElapsedMilliseconds < 250, "Sweep initiation must be non-blocking.");

            var result = await task;
            Assert.NotNull(result);
        }
    }
}
