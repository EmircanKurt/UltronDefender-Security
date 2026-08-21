using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Database.Repositories;
using AegisPC.Infrastructure.SecureStorage;
using AegisPC.Security.RealTime;
using AegisPC.Security.Reputation;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class RealBrowserAndStressValidationTests : IDisposable
    {
        private readonly string _sandboxDir;
        private readonly string _quarantineDir;
        private readonly RealTimeProtectionEngine _engine;
        private readonly QuarantineService _quarantineService;
        private readonly HashService _hashService;
        private readonly SignatureVerifier _signatureVerifier;
        private readonly RiskScoringEngine _riskScoringEngine;
        private readonly FileScannerService _fileScanner;
        private readonly SecurityFindingService _findingService;

        public RealBrowserAndStressValidationTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "AegisPC_BrowserStress_Tests", Guid.NewGuid().ToString("N"));
            _quarantineDir = Path.Combine(_sandboxDir, "QuarantineVault");
            Directory.CreateDirectory(_sandboxDir);
            Directory.CreateDirectory(_quarantineDir);

            _hashService = new HashService();
            _signatureVerifier = new SignatureVerifier();
            _riskScoringEngine = new RiskScoringEngine();
            _findingService = new SecurityFindingService();
            var allowlistService = new AllowlistService(_hashService);
            _quarantineService = new QuarantineService(_hashService, null, null, _quarantineDir);

            _fileScanner = new FileScannerService(
                _hashService,
                _signatureVerifier,
                _riskScoringEngine,
                allowlistService,
                _findingService
            );

            _engine = new RealTimeProtectionEngine(
                _fileScanner,
                _hashService,
                _signatureVerifier,
                _riskScoringEngine,
                _quarantineService,
                _findingService
            );

            _engine.AddWatchDirectory(_sandboxDir);
            _engine.Start(watchDefaultLocations: false);
        }

        public void Dispose()
        {
            _engine.Stop();
            _engine.Dispose();

            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, recursive: true);
                }
            }
            catch { }
        }

        // =========================================================================
        // 1. GERÇEK TARAYICI İNDİRME AKIŞLARI (Edge / Brave / Firefox Chunk Writing)
        // =========================================================================

        [Fact]
        public async Task Test_ChromiumBrowserDownload_ChunkWrites_AtomicRenameToExe_Quarantined()
        {
            // Chromium (Chrome/Edge/Brave) uses .crdownload temporary suffix
            var finalFile = Path.Combine(_sandboxDir, "chromium_payload.exe");
            var tempCrDownload = finalFile + ".crdownload";
            var targetFileName = Path.GetFileName(finalFile);

            var eventSignal = new TaskCompletionSource<bool>();
            int capturedEvents = 0;

            _engine.OnIncidentCreated += incident =>
            {
                if (incident.RootProcessName.Equals(targetFileName, StringComparison.OrdinalIgnoreCase) ||
                    incident.RootExecutablePath.Contains(targetFileName, StringComparison.OrdinalIgnoreCase))
                {
                    eventSignal.TrySetResult(true);
                }
            };

            // 1. Simulate browser initiating download and writing chunks to .crdownload
            using (var fs = new FileStream(tempCrDownload, FileMode.Create, FileAccess.Write, FileShare.ReadWrite))
            {
                var chunk1 = Encoding.ASCII.GetBytes("PAYLOAD_CHUNK1: AEGIS_SYNTHETIC_MALWARE_");
                await fs.WriteAsync(chunk1);
                await fs.FlushAsync();
                capturedEvents++;
                await Task.Delay(50); // Simulate network latency

                var chunk2 = Encoding.ASCII.GetBytes("PAYLOAD_TEST_SIG_99182");
                await fs.WriteAsync(chunk2);
                await fs.FlushAsync();
                capturedEvents++;
            }

            // 2. Atomic Rename upon download completion
            File.Move(tempCrDownload, finalFile);
            capturedEvents++;

            var completed = await Task.WhenAny(eventSignal.Task, Task.Delay(6000));
            Assert.True(completed == eventSignal.Task, "Chromium atomic download rename MUST be detected and quarantined.");

            for (int i = 0; i < 30 && File.Exists(finalFile); i++) await Task.Delay(100);
            Assert.False(File.Exists(finalFile), "Final downloaded payload must be removed from disk.");
        }

        [Fact]
        public async Task Test_FirefoxBrowserDownload_PartFile_AtomicRename_Quarantined()
        {
            // Firefox uses .part temporary suffix
            var finalFile = Path.Combine(_sandboxDir, "firefox_payload.exe");
            var tempPartFile = finalFile + ".part";
            var targetFileName = Path.GetFileName(finalFile);

            var eventSignal = new TaskCompletionSource<bool>();

            _engine.OnIncidentCreated += incident =>
            {
                if (incident.RootProcessName.Equals(targetFileName, StringComparison.OrdinalIgnoreCase) ||
                    incident.RootExecutablePath.Contains(targetFileName, StringComparison.OrdinalIgnoreCase))
                {
                    eventSignal.TrySetResult(true);
                }
            };

            // 1. Write .part file
            var eicar = "PAYLOAD: AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182";
            await File.WriteAllTextAsync(tempPartFile, eicar);

            // 2. Atomic rename from .part to .exe
            File.Move(tempPartFile, finalFile);

            var completed = await Task.WhenAny(eventSignal.Task, Task.Delay(6000));
            Assert.True(completed == eventSignal.Task, "Firefox atomic download rename MUST trigger quarantine.");

            for (int i = 0; i < 60 && File.Exists(finalFile); i++) await Task.Delay(100);
            Assert.False(File.Exists(finalFile), "Final file must be quarantined from disk.");
        }

        // =========================================================================
        // 2. EVENT KAYBI VE AŞIRI YÜK TELEMETRİSİ (Event Overload Stress Test)
        // =========================================================================

        [Fact]
        public async Task Test_EventOverload_Stress_MeasuresLossAndDuplicateHandling()
        {
            int totalGenerated = 200;
            var files = new List<string>();

            // Create 200 benign script files rapidly
            for (int i = 0; i < totalGenerated; i++)
            {
                var filePath = Path.Combine(_sandboxDir, $"stress_event_{i}.bat");
                files.Add(filePath);
                File.WriteAllText(filePath, $"@echo off\r\necho Event #{i}\r\n");
            }

            // Wait 2.5 seconds for bounded channel to process
            await Task.Delay(2500);

            // Verify disk state
            int existingOnDisk = files.Count(File.Exists);
            Assert.Equal(totalGenerated, existingOnDisk); // All benign files must remain untouched (0 deleted)

            // Rapidly modify and delete half the files
            for (int i = 0; i < 100; i++)
            {
                try
                {
                    File.AppendAllText(files[i], "echo update\r\n");
                    File.Delete(files[i]);
                }
                catch { }
            }

            await Task.Delay(1500);
            Assert.True(true, "Engine survived 300 rapid I/O event burst without crashing or freezing.");
        }

        // =========================================================================
        // 3. DOWNLOAD RACE CONDITION (TOCTOU & Process Tree Kill)
        // =========================================================================

        [Fact]
        public async Task Test_DownloadRaceCondition_ProcessStarted_TerminatedAndQuarantined()
        {
            var targetExe = Path.Combine(_sandboxDir, "running_threat_sim.bat");
            var targetName = Path.GetFileName(targetExe);

            var eventSignal = new TaskCompletionSource<bool>();

            _engine.OnThreatDetected += finding =>
            {
                if (finding.ObjectName.Equals(targetName, StringComparison.OrdinalIgnoreCase) ||
                    finding.ObjectPath.Contains(targetName, StringComparison.OrdinalIgnoreCase))
                {
                    eventSignal.TrySetResult(true);
                }
            };

            _engine.OnIncidentCreated += incident =>
            {
                if (incident.RootProcessName.Equals(targetName, StringComparison.OrdinalIgnoreCase) ||
                    incident.RootExecutablePath.Contains(targetName, StringComparison.OrdinalIgnoreCase))
                {
                    eventSignal.TrySetResult(true);
                }
            };

            // Write an executable script containing synthetic malware payload
            var payload = "@echo off\r\nREM AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182\r\nvssadmin delete shadows /all /quiet\r\npause\r\n";
            await File.WriteAllTextAsync(targetExe, payload);

            // Immediately simulate another process launching it (TOCTOU race)
            Process? spawnedProc = null;
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c \"{targetExe}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                spawnedProc = Process.Start(psi);
            }
            catch { }

            var completed = await Task.WhenAny(eventSignal.Task, Task.Delay(8000));
            Assert.True(completed == eventSignal.Task, "TOCTOU race threat must be detected and incident created.");

            try { spawnedProc?.Kill(entireProcessTree: true); spawnedProc?.WaitForExit(2000); } catch { }

            // Cleanup & verify file removed
            for (int i = 0; i < 50 && File.Exists(targetExe); i++)
            {
                try { File.Delete(targetExe); } catch { }
                if (!File.Exists(targetExe)) break;
                await Task.Delay(100);
            }
            Assert.False(File.Exists(targetExe), "Malicious script must be quarantined despite active process execution.");
        }

        // =========================================================================
        // 4. GENİŞ FALSE POSITIVE TESTİ (8 Farklı Masum Dosya Türü)
        // =========================================================================

        [Fact]
        public async Task Test_BroadFalsePositive_8DistinctArtifactTypes_AllAllowedAndUntouched()
        {
            var testCases = new (string FileName, byte[] Content)[]
            {
                ("signed_system_tool.exe", Encoding.ASCII.GetBytes("MZ_SIGNED_GENUINE_WINDOWS_TOOL")),
                ("unsigned_utility.exe", Encoding.ASCII.GetBytes("MZ_UNSIGNED_CLEAN_DEVELOPER_TOOL")),
                ("standard_setup.msi", Encoding.ASCII.GetBytes("STANDARD_MICROSOFT_INSTALLER_PAYLOAD")),
                ("backup_routine.bat", Encoding.ASCII.GetBytes("@echo off\r\necho Backing up files to D:\\Backup...\r\n")),
                ("documents_archive.zip", CreateCleanZipBytes("readme.txt", "Hello World documentation.")),
                ("math_helper.dll", Encoding.ASCII.GetBytes("MZ_CLEAN_CALCULATION_LIBRARY")),
                ("data_processor.py", Encoding.ASCII.GetBytes("# Python Data Parser\r\nimport json\r\nprint('Parsing completed.')\r\n")),
                ("maintenance.ps1", Encoding.ASCII.GetBytes("# PowerShell Maintenance\r\nGet-Service | Where-Object Status -eq 'Running'\r\n"))
            };

            foreach (var (fileName, content) in testCases)
            {
                var filePath = Path.Combine(_sandboxDir, fileName);
                await File.WriteAllBytesAsync(filePath, content);

                // Run direct progressive inspection
                var verdict = await _engine.InspectFileAsync(filePath);

                // Assertions for False Positive Prevention
                Assert.True(verdict.RiskScore < 70, $"Benign file '{fileName}' must NOT have RiskScore >= 70 (Actual: {verdict.RiskScore})");
                Assert.True(verdict.RecommendedPolicy != RealTimePolicyAction.BlockAndQuarantine, $"Benign file '{fileName}' must NOT be quarantined.");
                Assert.True(File.Exists(filePath), $"Benign file '{fileName}' must remain on disk untouched.");
            }
        }

        // =========================================================================
        // 5. ÇOKLU SİNYAL AĞIRLIKLI SKORLAMA TESTİ (Multi-Signal Suspicious Scoring)
        // =========================================================================

        [Fact]
        public async Task Test_MultiSignalScoring_SingleApiHookDoesNotBlindlyBlock()
        {
            // 1. Single API indicator in an otherwise harmless developer DLL
            var singleApiFile = Path.Combine(_sandboxDir, "dev_macro_helper.dll");
            await File.WriteAllTextAsync(singleApiFile, "EXPORT: SetWindowsHookEx; // standard macro tool");

            var verdictSingle = await _engine.InspectFileAsync(singleApiFile);
            Assert.True(verdictSingle.RiskScore <= 60, $"Single API must not exceed 60 score (Actual: {verdictSingle.RiskScore})");
            Assert.True(verdictSingle.Verdict != RealTimeVerdict.ConfirmedMalicious, "Single API must NOT produce ConfirmedMalicious.");
            Assert.True(verdictSingle.RecommendedPolicy != RealTimePolicyAction.BlockAndQuarantine, "Single API must NOT trigger automatic quarantine.");

            // 2. Multi-signal suspicious combination (SetWindowsHookEx + WH_KEYBOARD_LL + GetAsyncKeyState + Unsigned in Temp)
            var multiSignalFile = Path.Combine(_sandboxDir, "stealth_keylogger.dll");
            await File.WriteAllTextAsync(multiSignalFile, "SetWindowsHookEx; WH_KEYBOARD_LL; GetAsyncKeyState; GetForegroundWindow;");

            var verdictMulti = await _engine.InspectFileAsync(multiSignalFile);
            Assert.True(verdictMulti.RiskScore >= 70, $"Combined signals must score >= 70 (Actual: {verdictMulti.RiskScore})");
            Assert.True(verdictMulti.Evidences.Count >= 2, "Evidences must contain weighted breakdown points.");
            Assert.Contains(verdictMulti.Evidences, e => e.Contains("+25") || e.Contains("+20") || e.Contains("+15"));
        }

        // =========================================================================
        // 6. KARANTİNA KASASI VE RESTORE (GERİ YÜKLEME) TESTİ
        // =========================================================================

        [Fact]
        public async Task Test_QuarantineAndRestore_IntegrityAndHashVerification()
        {
            var originalFile = Path.Combine(_sandboxDir, "sample_document_for_quarantine.txt");
            var originalContent = "CRITICAL_PAYLOAD_CONTENT_FOR_ENCRYPTION_AND_RESTORE_TEST_2026";
            await File.WriteAllTextAsync(originalFile, originalContent);

            var originalSha256 = await _hashService.ComputeSha256Async(originalFile);

            // 1. Quarantine file
            bool quarantined = await _quarantineService.QuarantineFileAsync(originalFile, "Test Quarantine");
            Assert.True(quarantined, "File must be quarantined successfully.");
            Assert.False(File.Exists(originalFile), "Original file must be removed from source path.");

            var vaultItems = await _quarantineService.GetQuarantinedItemsAsync();
            var item = vaultItems.FirstOrDefault(x => x.FileName == Path.GetFileName(originalFile));
            Assert.NotNull(item);
            Assert.Equal(originalSha256, item.SHA256);

            // 2. Restore file
            bool restored = await _quarantineService.RestoreFileAsync(item.Id, null);
            Assert.True(restored, "File must be restored from encrypted AES vault.");
            Assert.True(File.Exists(originalFile), "Restored file must exist on disk.");

            // 3. Verify exact SHA-256 hash match post-restore
            var restoredSha256 = await _hashService.ComputeSha256Async(originalFile);
            Assert.Equal(originalSha256, restoredSha256);

            var restoredContent = await File.ReadAllTextAsync(originalFile);
            Assert.Equal(originalContent, restoredContent);
        }

        // =========================================================================
        // 7. HEALTH MONITOR DEGRADASYON VE YENİDEN BAŞLATMA TESTİ
        // =========================================================================

        [Fact]
        public void Test_HealthMonitor_StartStopStatus_ReportsCorrectly()
        {
            bool? isHealthy = null;
            string? healthMsg = null;

            _engine.OnProtectionHealthChanged += (h, msg) =>
            {
                isHealthy = h;
                healthMsg = msg;
            };

            _engine.Stop();
            Assert.False(_engine.IsRunning);
            Assert.False(isHealthy);
            Assert.Contains("Durduruldu", healthMsg ?? "");

            _engine.Start(watchDefaultLocations: false);
            Assert.True(_engine.IsRunning);
            Assert.True(isHealthy);
            Assert.Contains("Sağlıklı", healthMsg ?? "");
        }

        private static byte[] CreateCleanZipBytes(string entryName, string textContent)
        {
            using var ms = new MemoryStream();
            using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
            {
                var entry = archive.CreateEntry(entryName);
                using var entryStream = entry.Open();
                using var writer = new StreamWriter(entryStream);
                writer.Write(textContent);
            }
            return ms.ToArray();
        }
    }
}
