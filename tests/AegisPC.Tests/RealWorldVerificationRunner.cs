using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Notifications;
using AegisPC.Security.Scanning;
using Xunit;
using Xunit.Abstractions;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class RealWorldVerificationRunner : IDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly string _testRoot;
        private readonly FileScannerService _scanner;
        private readonly QuarantineService _quarantineService;

        public RealWorldVerificationRunner(ITestOutputHelper output)
        {
            _output = output;
            _testRoot = Path.Combine(Path.GetTempPath(), "UltronRealWorldTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testRoot);

            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var riskEngine = new RiskScoringEngine();
            var allowlist = new AllowlistService(hashService);
            var findingService = new SecurityFindingService();
            var detectionHub = DetectionHubFactory.CreateDefault(hashService, sigVerifier);

            _scanner = new FileScannerService(
                hashService,
                sigVerifier,
                riskEngine,
                allowlist,
                findingService,
                detectionHub);

            _quarantineService = new QuarantineService(hashService, customVaultDir: Path.Combine(_testRoot, "Vault"));
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testRoot))
                {
                    Directory.Delete(_testRoot, recursive: true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Test_RealWorld_FullScan_DropZones_And_LockedFiles()
        {
            _output.WriteLine("===============================================================");
            _output.WriteLine("ULTRON DEFENDER TOTAL SECURITY - REAL WINDOWS VERIFICATION GATE");
            _output.WriteLine("===============================================================");

            // 1. Check Real Installed Browsers on Host
            _output.WriteLine("\n[1] REAL BROWSER INVENTORY AUDIT:");
            string[] possibleBrowsers = new[]
            {
                @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                @"C:\Program Files\Mozilla Firefox\firefox.exe"
            };
            foreach (var bPath in possibleBrowsers)
            {
                bool exists = File.Exists(bPath);
                _output.WriteLine($"Browser: {Path.GetFileNameWithoutExtension(bPath)} => {(exists ? "INSTALLED (" + bPath + ")" : "NOT INSTALLED")}");
            }

            // 2. Real Filesystem Fixture Drop & Full Scan
            _output.WriteLine("\n[2] REAL FILESYSTEM DROP ZONE FULL SCAN AUDIT:");
            string desktopDir = Path.Combine(_testRoot, "Desktop");
            string downloadsDir = Path.Combine(_testRoot, "Downloads");
            string tempDir = Path.Combine(_testRoot, "Temp");
            Directory.CreateDirectory(desktopDir);
            Directory.CreateDirectory(downloadsDir);
            Directory.CreateDirectory(tempDir);

            // File 1: Disguised PE with .dat extension on Desktop
            string f1 = Path.Combine(desktopDir, "trojan_payload.dat");
            await File.WriteAllTextAsync(f1, "AEGIS_SYNTHETIC_MALWARE_PAYLOAD_TEST_SIG_99182");

            // File 2: Keylogger static indicator on Desktop (Base64 encoded to prevent host AV locking during build)
            string f2 = Path.Combine(desktopDir, "stealth_keylog.exe");
            var keylogPayload = Encoding.UTF8.GetString(Convert.FromBase64String("TVouLi5TZXRXaW5kb3dzSG9va0V4Vy4uLkdldEtleWJvYXJkU3RhdGUuLi5Ub1VuaWNvZGUuLi5XSF9LRVlCT0FSRF9MTA=="));
            await File.WriteAllTextAsync(f2, keylogPayload);

            // File 3: Script Heuristic threat in Downloads (Base64 encoded)
            string f3 = Path.Combine(downloadsDir, "destroy_backup.bat");
            var scriptPayload = Encoding.UTF8.GetString(Convert.FromBase64String("dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL2FsbCAvcXVpZXQ="));
            await File.WriteAllTextAsync(f3, scriptPayload);

            // File 4: Benign text file in Documents/Temp
            string f4 = Path.Combine(tempDir, "benign_document.txt");
            await File.WriteAllTextAsync(f4, "This is a legitimate clean user document.");

            var sw = Stopwatch.StartNew();
            var scanResult = await _scanner.ScanDirectoryAsync(_testRoot, ScanType.Custom);
            sw.Stop();

            _output.WriteLine($"Total Files Enumerated: {scanResult.TotalFiles}");
            _output.WriteLine($"Total Files Scanned:    {scanResult.ScannedFiles}");
            _output.WriteLine($"Total Threats Found:    {scanResult.Findings.Count}");
            _output.WriteLine($"Scan Duration (ms):     {sw.ElapsedMilliseconds} ms");

            Assert.True(scanResult.TotalFiles >= 4);
            Assert.True(scanResult.Findings.Count >= 3);

            foreach (var f in scanResult.Findings)
            {
                _output.WriteLine($" -> DETECTED: [{f.RiskLevel}] {f.ObjectName} (Score: {f.RiskScore}/100) - {f.Title}");
            }

            // 3. Locked File Handling Test
            _output.WriteLine("\n[3] LOCKED FILE HANDLING TEST:");
            string lockedFilePath = Path.Combine(tempDir, "locked_sample.exe");
            await File.WriteAllTextAsync(lockedFilePath, "MZ...LockedContentTest...");
            using (var fileStream = new FileStream(lockedFilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                var lockedFinding = await _scanner.ScanFileAsync(lockedFilePath);
                _output.WriteLine($"Locked File Scanned Result: {(lockedFinding != null ? "SCANNED (Threat/Warning)" : "SCANNED (Clean - No Crash)")}");
            }

            // 4. Quarantine 20 Threats & Batch Notification Audit
            _output.WriteLine("\n[4] 20-THREAT BATCH QUARANTINE & NOTIFICATION AUDIT:");
            var toastList = new List<string>();
            var mockToast = new MockToast(toastList);
            using var aggregator = new NotificationAggregator(mockToast)
            {
                AggregationWindow = TimeSpan.FromMilliseconds(500)
            };

            for (int i = 1; i <= 20; i++)
            {
                string dummyThreat = Path.Combine(tempDir, $"batch_threat_{i}.exe");
                await File.WriteAllTextAsync(dummyThreat, "MZ_THREAT_PAYLOAD");
                bool qOk = await _quarantineService.QuarantineFileAsync(dummyThreat, $"Batch Threat #{i}");
                Assert.True(qOk, $"Quarantine failed on item {i}");
                aggregator.PushThreatEvent($"Threat #{i}", dummyThreat, "Quarantined", isCritical: false);
            }

            await Task.Delay(700); // Wait for aggregator flush

            _output.WriteLine($"Total Threats Pushed:   20");
            _output.WriteLine($"Total Notifications Fired: {toastList.Count} (Expected: Aggregated Batch Notification)");
            Assert.InRange(toastList.Count, 1, 3);
            _output.WriteLine($" -> TOAST EMITTED: {toastList[0]}");

            // 5. Driver / Kernel Reality Audit
            _output.WriteLine("\n[5] KERNEL DRIVER REALITY AUDIT:");
            string driverSrc = @"c:\Users\PC\Documents\gemini virüs program\drivers";
            bool driverDirExists = Directory.Exists(driverSrc);
            bool sysExists = File.Exists(Path.Combine(driverSrc, "AegisFilter.sys"));
            _output.WriteLine($"Driver Source Directory: {(driverDirExists ? "EXISTS (C Source Files)" : "NOT FOUND")}");
            _output.WriteLine($"Compiled .sys Binary:    {(sysExists ? "FOUND" : "NOT FOUND (Uncompiled C source)")}");
            _output.WriteLine("Kernel Gating Status:    UNVERIFIED / NOT ACTIVE (User-mode FileSystemWatcher active)");
        }

        private class MockToast : IWindowsToastNotificationService
        {
            private readonly List<string> _list;
            public MockToast(List<string> list) => _list = list;
            public void ShowToast(string title, string message, string type = "Info")
            {
                lock (_list) _list.Add($"[{type.ToUpper()}] {title} | {message.Replace("\n", " ")}");
            }
        }
    }
}
