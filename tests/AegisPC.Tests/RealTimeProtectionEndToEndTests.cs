using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    /// <summary>
    /// FileSystemWatcher tabanlı Gerçek Zamanlı Koruma motorunun
    /// iç fonksiyonları manuel çağırmadan (Zero-Mock), doğrudan OS dosya sistemi
    /// olayları üzerinden (Created -> Watcher -> Channel -> Quarantine) uçtan uca testleri.
    /// </summary>
    [Collection("SequentialDiskTests")]
    public class RealTimeProtectionEndToEndTests : IDisposable
    {
        private readonly string _testSandboxDir;
        private readonly string _vaultDir;
        private readonly IHashService _hashService;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IRiskScoringEngine _riskScoringEngine;
        private readonly IAllowlistService _allowlistService;
        private readonly IQuarantineService _quarantineService;
        private readonly ISecurityFindingService _findingService;
        private readonly IFileScanner _fileScanner;
        private readonly RealTimeProtectionEngine _engine;

        public RealTimeProtectionEndToEndTests()
        {
            _testSandboxDir = Path.Combine(Path.GetTempPath(), "AegisE2ETests_" + Guid.NewGuid().ToString("N"));
            _vaultDir = Path.Combine(_testSandboxDir, "Vault");
            Directory.CreateDirectory(_testSandboxDir);
            Directory.CreateDirectory(_vaultDir);

            _hashService = new HashService();
            _signatureVerifier = new SignatureVerifier();
            _riskScoringEngine = new RiskScoringEngine();
            _findingService = new SecurityFindingService();
            _allowlistService = new AllowlistService(_hashService);
            _quarantineService = new QuarantineService(_hashService, null, null, _vaultDir);
            _fileScanner = new FileScannerService(_hashService, _signatureVerifier, _riskScoringEngine, _allowlistService, _findingService);

            _engine = new RealTimeProtectionEngine(
                _fileScanner,
                _hashService,
                _signatureVerifier,
                _riskScoringEngine,
                _quarantineService,
                _findingService);

            // Attach watcher to test directory before starting the live background protection loop
            _engine.AddWatchDirectory(_testSandboxDir);
            _engine.Start(watchDefaultLocations: false);
        }

        [Fact]
        public async Task Test1_E2E_EicarFileCreation_TriggeredByWatcher_QuarantinedAutomatically()
        {
            var targetFile = Path.Combine(_testSandboxDir, "eicar_e2e_download.com");
            var targetFileName = Path.GetFileName(targetFile);

            SecurityFinding? capturedFinding = null;
            SecurityIncident? capturedIncident = null;
            var eventSignal = new TaskCompletionSource<bool>();

            _engine.OnThreatDetected += finding =>
            {
                if (finding.ObjectName.Equals(targetFileName, StringComparison.OrdinalIgnoreCase) || finding.ObjectPath.Contains(targetFileName, StringComparison.OrdinalIgnoreCase))
                {
                    capturedFinding = finding;
                }
            };

            _engine.OnIncidentCreated += incident =>
            {
                if (incident.RootProcessName.Equals(targetFileName, StringComparison.OrdinalIgnoreCase) || incident.RootExecutablePath.Contains(targetFileName, StringComparison.OrdinalIgnoreCase))
                {
                    capturedIncident = incident;
                    eventSignal.TrySetResult(true);
                }
            };
            // 2. Act: Create synthetic test malware file in watched directory (Simulating OS File Drop)
            var eicarString = "PAYLOAD: AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182";
            await File.WriteAllTextAsync(targetFile, eicarString);

            // 3. Wait for FileSystemWatcher -> Channel -> Inspection -> Quarantine pipeline
            var completedTask = await Task.WhenAny(eventSignal.Task, Task.Delay(6000));
            Assert.True(completedTask == eventSignal.Task, "FileSystemWatcher must capture file creation and trigger quarantine within 6 seconds.");

            // 4. Assert Live Detection Details
            Assert.NotNull(capturedFinding);
            Assert.Contains("TestThreat", capturedFinding.Title);
            Assert.Equal(FindingStatus.Resolved, capturedFinding.Status);

            Assert.NotNull(capturedIncident);
            Assert.Equal("Quarantined", capturedIncident.Status);

            // 5. Assert File System State (Original removed, vault populated)
            for (int i = 0; i < 30 && File.Exists(targetFile); i++)
            {
                await Task.Delay(100);
            }
            Assert.False(File.Exists(targetFile), "Original malicious file MUST be removed from arrival directory by the live watcher engine.");

            var vaultItems = await _quarantineService.GetQuarantinedItemsAsync();
            Assert.True(vaultItems.Count > 0, "Quarantine vault must contain the secured threat entry.");
        }

        [Fact]
        public async Task Test2_E2E_BenignExecutableCreation_AllowedAndPreserved()
        {
            var targetFile = Path.Combine(_testSandboxDir, "clean_app_download.exe");
            bool threatFired = false;

            _engine.OnThreatDetected += finding =>
            {
                if (finding.ObjectName.Equals(Path.GetFileName(targetFile), StringComparison.OrdinalIgnoreCase))
                {
                    threatFired = true;
                }
            };

            var benignContent = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00CleanBenignExecutablePayloadForE2E";
            await File.WriteAllTextAsync(targetFile, benignContent);

            await Task.Delay(1500);

            Assert.False(threatFired, "Benign executable must NOT trigger threat alert.");
            Assert.True(File.Exists(targetFile), "Benign executable must remain untouched on disk.");
        }

        [Fact]
        public async Task Test3_E2E_ControlledKeyloggerBehavior_TriggeredByWatcher_Quarantined()
        {
            var uniqueId = Guid.NewGuid().ToString("N")[..6];
            var targetFile = Path.Combine(_testSandboxDir, $"win_synthetic_driver_{uniqueId}.exe");
            var targetFileName = Path.GetFileName(targetFile);

            SecurityFinding? capturedFinding = null;
            var eventSignal = new TaskCompletionSource<bool>();

            _engine.OnThreatDetected += finding =>
            {
                if (finding.ObjectName.Equals(targetFileName, StringComparison.OrdinalIgnoreCase) || finding.ObjectPath.Equals(targetFile, StringComparison.OrdinalIgnoreCase))
                {
                    capturedFinding = finding;
                    eventSignal.TrySetResult(true);
                }
            };

            _engine.OnIncidentCreated += incident =>
            {
                if (incident.RootProcessName.Equals(targetFileName, StringComparison.OrdinalIgnoreCase) || incident.RootExecutablePath.Equals(targetFile, StringComparison.OrdinalIgnoreCase))
                {
                    eventSignal.TrySetResult(true);
                }
            };

            var payload = "EXPORT_HOOK: SetWindowsHookEx(WH_KEYBOARD_LL, HookProc, hInst, 0); GetAsyncKeyState(VK_TAB); PAYLOAD: AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182";
            await File.WriteAllTextAsync(targetFile, payload);

            var completedTask = await Task.WhenAny(eventSignal.Task, Task.Delay(10000));
            Assert.True(completedTask == eventSignal.Task, "Keylogger signature MUST be detected and processed by live watcher pipeline.");

            Assert.NotNull(capturedFinding);

            for (int i = 0; i < 50 && File.Exists(targetFile); i++)
            {
                await Task.Delay(100);
            }
            Assert.False(File.Exists(targetFile), "Keylogger file must be quarantined from disk.");
        }

        [Fact]
        public async Task Test4_E2E_SuspiciousScript_WarnPolicy_NeverDeletesFile()
        {
            var targetFile = Path.Combine(_testSandboxDir, "suspicious_autorun.bat");
            var targetFileName = Path.GetFileName(targetFile);

            string? notificationTitle = null;
            var eventSignal = new TaskCompletionSource<bool>();

            _engine.OnNotificationRaised += (title, msg, type) =>
            {
                if (msg.Contains(targetFileName, StringComparison.OrdinalIgnoreCase))
                {
                    notificationTitle = title;
                    eventSignal.TrySetResult(true);
                }
            };

            var payload = "@echo off\n powershell -ExecutionPolicy Bypass -NoProfile -Command \"Write-Host 'Test'\"";
            await File.WriteAllTextAsync(targetFile, payload);

            await Task.WhenAny(eventSignal.Task, Task.Delay(3000));

            // CRITICAL: File must remain on disk, NOT deleted
            Assert.True(File.Exists(targetFile), "Suspicious/low confidence files must NEVER be deleted automatically without policy.");
        }

        public void Dispose()
        {
            _engine.Stop();
            _engine.Dispose();
            try
            {
                if (Directory.Exists(_testSandboxDir))
                {
                    Directory.Delete(_testSandboxDir, recursive: true);
                }
            }
            catch { }
        }
    }
}
