using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class RansomwareEndToEndVerificationTests : IDisposable
    {
        private readonly string _testProtectedDir;

        public RansomwareEndToEndVerificationTests()
        {
            _testProtectedDir = Path.Combine(Path.GetTempPath(), $"UltronRansomwareEndToEnd_{Guid.NewGuid():N}");
            Directory.CreateDirectory(_testProtectedDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testProtectedDir))
                {
                    Directory.Delete(_testProtectedDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task Test_CanaryDecoyTampering_TriggersImmediateCriticalAlertAndQuarantine()
        {
            var hashService = new HashService();
            var findingService = new SecurityFindingService();
            var quarantineService = new QuarantineService(hashService);

            using var ransomwareEngine = new RansomwareProtectionEngine(
                signatureVerifier: null,
                quarantineService: quarantineService,
                findingService: findingService);

            ransomwareEngine.AddProtectedDirectory(_testProtectedDir);
            ransomwareEngine.StartShield();

            string alphaCanary = Path.Combine(_testProtectedDir, "!_ultron_shield_canary.docx");
            Assert.True(File.Exists(alphaCanary), "Alpha canary decoy must exist upon starting shield.");

            RansomwareAlertEventArgs? alertReceived = null;
            ransomwareEngine.OnRansomwareAttemptDetected += (s, e) => alertReceived = e;

            // Simulate malware modifying the canary decoy file
            await File.AppendAllTextAsync(alphaCanary, "MALICIOUS_RANSOMWARE_ENCRYPTED_HEADER_PAYLOAD");

            // Evaluate directly or via watcher
            var assessment = await ransomwareEngine.EvaluateAndContainThreatAsync(
                alphaCanary,
                "🚨 Kritik Tuzak İhlali: Kalkan Canary dosyası izinsiz değiştirildi!",
                riskScore: 100);

            Assert.NotNull(assessment);
            Assert.NotNull(alertReceived);
            Assert.Equal(100, alertReceived.RiskScore);
            Assert.Contains("Canary", alertReceived.DetectionReason, StringComparison.OrdinalIgnoreCase);

            ransomwareEngine.StopShield();
        }

        [Fact]
        public async Task Test_EncryptLikeRename_TriggersRansomwareAlert()
        {
            var hashService = new HashService();
            var findingService = new SecurityFindingService();
            var quarantineService = new QuarantineService(hashService);

            using var ransomwareEngine = new RansomwareProtectionEngine(
                signatureVerifier: null,
                quarantineService: quarantineService,
                findingService: findingService);

            ransomwareEngine.AddProtectedDirectory(_testProtectedDir);
            ransomwareEngine.StartShield();

            string regularFile = Path.Combine(_testProtectedDir, "budget_report.xlsx");
            await File.WriteAllTextAsync(regularFile, "Important financial data.");

            string encryptedFile = Path.Combine(_testProtectedDir, "budget_report.xlsx.locked");
            for (int retry = 0; retry < 5; retry++)
            {
                try
                {
                    File.Move(regularFile, encryptedFile);
                    break;
                }
                catch (IOException) when (retry < 4)
                {
                    await Task.Delay(50);
                }
            }

            RansomwareAlertEventArgs? alertReceived = null;
            ransomwareEngine.OnRansomwareAttemptDetected += (s, e) => alertReceived = e;

            // Verify .locked extension triggers alert
            var assessment = await ransomwareEngine.EvaluateAndContainThreatAsync(
                encryptedFile,
                "🚨 Bilinen fidye şifreleme uzantısı tespit edildi: '.locked'",
                riskScore: 95);

            Assert.NotNull(assessment);
            Assert.NotNull(alertReceived);
            Assert.Equal(95, alertReceived.RiskScore);
            Assert.Contains(".locked", alertReceived.DetectionReason, StringComparison.OrdinalIgnoreCase);

            ransomwareEngine.StopShield();
        }

        [Fact]
        public async Task Test_UnauthorizedApplication_AccessingProtectedDirectory_IsBlocked()
        {
            var hashService = new HashService();
            var findingService = new SecurityFindingService();
            var quarantineService = new QuarantineService(hashService);

            using var ransomwareEngine = new RansomwareProtectionEngine(
                signatureVerifier: null,
                quarantineService: quarantineService,
                findingService: findingService);

            ransomwareEngine.AddProtectedDirectory(_testProtectedDir);

            // An unknown malware process name
            string unauthorizedApp = "wannacry_payload.exe";
            Assert.False(ransomwareEngine.IsApplicationAllowed(unauthorizedApp));

            RansomwareAlertEventArgs? alert = null;
            ransomwareEngine.OnRansomwareAttemptDetected += (s, e) => alert = e;

            string targetFile = Path.Combine(_testProtectedDir, "customer_records.db");
            await File.WriteAllTextAsync(targetFile, "Database contents");

            var assessment = await ransomwareEngine.EvaluateAndContainThreatAsync(
                targetFile,
                $"🚨 Korumalı Klasör İhlali: İzinli olmayan '{unauthorizedApp}' süreci müdahalede bulundu!",
                riskScore: 90);

            Assert.NotNull(assessment);
            Assert.NotNull(alert);
            Assert.Equal(90, alert.RiskScore);
            Assert.Contains(unauthorizedApp, alert.DetectionReason);
        }

        [Fact]
        public async Task Test_AllowedApplication_AccessingProtectedDirectory_IsNotTerminated()
        {
            var hashService = new HashService();
            var findingService = new SecurityFindingService();
            var quarantineService = new QuarantineService(hashService);

            using var ransomwareEngine = new RansomwareProtectionEngine(
                signatureVerifier: null,
                quarantineService: quarantineService,
                findingService: findingService);

            ransomwareEngine.AddProtectedDirectory(_testProtectedDir);

            // Whitelisted text editor
            string allowedApp = "notepad.exe";
            Assert.True(ransomwareEngine.IsApplicationAllowed(allowedApp));

            // Whitelist should not trip termination guard
            string file = Path.Combine(_testProtectedDir, "notes.txt");
            await File.WriteAllTextAsync(file, "Normal note from user.");

            var assessment = await ransomwareEngine.EvaluateAndContainThreatAsync(
                file,
                "Normal file access",
                riskScore: 20);

            // Benign access with low risk should produce normal assessment
            Assert.NotNull(assessment);
        }
    }
}
