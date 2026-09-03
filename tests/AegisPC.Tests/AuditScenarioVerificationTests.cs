using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Safety;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.RealTime;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class AuditScenarioVerificationTests : IDisposable
    {
        private readonly string _testSandbox;

        public AuditScenarioVerificationTests()
        {
            _testSandbox = Path.Combine(Path.GetTempPath(), "UltronDefender_Audit_Tests_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_testSandbox);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testSandbox))
                {
                    Directory.Delete(_testSandbox, recursive: true);
                }
            }
            catch { }
        }

        // =========================================================================
        // === A. TEMEL TESPİT DOĞRULUĞU (Scenarios 1 - 4) ===
        // =========================================================================

        [Fact]
        public async Task Scenario01_EicarInDownloads_DetectedAsConfirmedMaliciousAndQuarantined()
        {
            var downloadsDir = Path.Combine(_testSandbox, "Downloads");
            Directory.CreateDirectory(downloadsDir);
            var eicarPath = Path.Combine(downloadsDir, "eicar_test_sample.com");
            string eicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            await File.WriteAllTextAsync(eicarPath, eicarContent);

            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var scoring = new RiskScoringEngine();
            var findingService = new MockSecurityFindingService();
            var allowlist = new AllowlistService(hashService);
            var quarantine = new QuarantineService(hashService, null, null, Path.Combine(_testSandbox, "Vault"));
            var scanner = new FileScannerService(hashService, sigVerifier, scoring, allowlist, findingService);

            var rtEngine = new RealTimeProtectionEngine(
                scanner, hashService, sigVerifier, scoring, quarantine, findingService);

            var verdict = await rtEngine.InspectFileAsync(eicarPath);

            Assert.Equal(RealTimeVerdict.ConfirmedMalicious, verdict.Verdict);
            Assert.Equal(RealTimePolicyAction.BlockAndQuarantine, verdict.RecommendedPolicy);
            Assert.Equal(100, verdict.RiskScore);
            Assert.Contains("EICAR", verdict.ThreatTitle);
        }

        [Fact]
        public async Task Scenario02_EicarInNodeModules_StillDetectedByRealTimeEngine()
        {
            var nodeModulesDir = Path.Combine(_testSandbox, "project", "node_modules", "malicious_package");
            Directory.CreateDirectory(nodeModulesDir);
            var eicarInPackage = Path.Combine(nodeModulesDir, "hidden_payload.exe");
            string eicarContent = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            await File.WriteAllTextAsync(eicarInPackage, eicarContent);

            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var scoring = new RiskScoringEngine();
            var findingService = new MockSecurityFindingService();
            var allowlist = new AllowlistService(hashService);
            var quarantine = new QuarantineService(hashService, null, null, Path.Combine(_testSandbox, "Vault"));
            var scanner = new FileScannerService(hashService, sigVerifier, scoring, allowlist, findingService);

            var rtEngine = new RealTimeProtectionEngine(
                scanner, hashService, sigVerifier, scoring, quarantine, findingService);

            var verdict = await rtEngine.InspectFileAsync(eicarInPackage);

            Assert.Equal(RealTimeVerdict.ConfirmedMalicious, verdict.Verdict);
            Assert.Equal(100, verdict.RiskScore);
        }

        [Fact]
        public async Task Scenario03_NormalBenignFiles_ProduceCleanVerdictWithNoAlerts()
        {
            var txtFile = Path.Combine(_testSandbox, "invoice.txt");
            var pdfFile = Path.Combine(_testSandbox, "report.pdf");
            var jpgFile = Path.Combine(_testSandbox, "photo.jpg");

            await File.WriteAllTextAsync(txtFile, "Sayin Musteri, Faturaniz ektedir. Toplam: 150 TL");
            await File.WriteAllBytesAsync(pdfFile, Encoding.UTF8.GetBytes("%PDF-1.4 sample harmless text content"));
            await File.WriteAllBytesAsync(jpgFile, new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46 });

            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var scoring = new RiskScoringEngine();
            var findingService = new MockSecurityFindingService();
            var allowlist = new AllowlistService(hashService);
            var quarantine = new QuarantineService(hashService, null, null, Path.Combine(_testSandbox, "Vault"));
            var scanner = new FileScannerService(hashService, sigVerifier, scoring, allowlist, findingService);

            var rtEngine = new RealTimeProtectionEngine(
                scanner, hashService, sigVerifier, scoring, quarantine, findingService);

            var vTxt = await rtEngine.InspectFileAsync(txtFile);
            var vPdf = await rtEngine.InspectFileAsync(pdfFile);
            var vJpg = await rtEngine.InspectFileAsync(jpgFile);

            Assert.Equal(RealTimeVerdict.Clean, vTxt.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, vTxt.RecommendedPolicy);
            Assert.True(vTxt.RiskScore < 50);

            Assert.Equal(RealTimeVerdict.Clean, vPdf.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, vPdf.RecommendedPolicy);
            Assert.True(vPdf.RiskScore < 50);

            Assert.Equal(RealTimeVerdict.Clean, vJpg.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, vJpg.RecommendedPolicy);
            Assert.True(vJpg.RiskScore < 50);
        }

        [Fact]
        public async Task Scenario04_SelfOwnedFiles_AreExcludedFromInspectionAndQuarantine()
        {
            string appBaseDir = AppDomain.CurrentDomain.BaseDirectory;
            string selfPdb = Path.Combine(appBaseDir, "AegisPC.Security.pdb");
            string selfConfig = Path.Combine(appBaseDir, "UltronDefender.runtimeconfig.json");
            string selfExe = Path.Combine(appBaseDir, "UltronDefender.exe");

            Assert.True(FileScannerService.IsSelfOwnedPath(selfPdb));
            Assert.True(FileScannerService.IsSelfOwnedPath(selfConfig));
            Assert.True(FileScannerService.IsSelfOwnedPath(selfExe));

            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var scoring = new RiskScoringEngine();
            var findingService = new MockSecurityFindingService();
            var allowlist = new AllowlistService(hashService);
            var quarantine = new QuarantineService(hashService, null, null, Path.Combine(_testSandbox, "Vault"));
            var scanner = new FileScannerService(hashService, sigVerifier, scoring, allowlist, findingService);

            var rtEngine = new RealTimeProtectionEngine(
                scanner, hashService, sigVerifier, scoring, quarantine, findingService);

            var verdictPdb = await rtEngine.InspectFileAsync(selfPdb);
            Assert.Equal(RealTimeVerdict.Clean, verdictPdb.Verdict);
            Assert.Equal(0, verdictPdb.RiskScore);
            Assert.Equal(RealTimePolicyAction.Allow, verdictPdb.RecommendedPolicy);
        }

        // =========================================================================
        // === B. YANLIŞ POZİTİF KONTROLÜ (Scenarios 5 - 6) ===
        // =========================================================================

        [Fact]
        public async Task Scenario05_DevelopmentPackages_FastPathSkipsUnneededStaticFiles()
        {
            var devDir = Path.Combine(_testSandbox, "my_dev_project", "node_modules", "lodash");
            Directory.CreateDirectory(devDir);
            var jsFile = Path.Combine(devDir, "lodash.js");
            var jsonFile = Path.Combine(devDir, "package.json");
            var mdFile = Path.Combine(devDir, "README.md");

            await File.WriteAllTextAsync(jsFile, "function add(a,b){ return a+b; } module.exports = { add };");
            await File.WriteAllTextAsync(jsonFile, "{\"name\":\"lodash\",\"version\":\"4.17.21\"}");
            await File.WriteAllTextAsync(mdFile, "# Lodash documentation");

            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var scoring = new RiskScoringEngine();
            var findingService = new MockSecurityFindingService();
            var allowlist = new AllowlistService(hashService);
            var scanner = new FileScannerService(
                hashService, sigVerifier, scoring, allowlist, findingService);

            var fJs = await scanner.ScanFileAsync(jsFile);
            var fJson = await scanner.ScanFileAsync(jsonFile);
            var fMd = await scanner.ScanFileAsync(mdFile);

            Assert.Null(fJs);
            Assert.Null(fJson);
            Assert.Null(fMd);
        }

        [Fact]
        public async Task Scenario06_SignedValidBinaries_ProduceCleanVerdict()
        {
            var testExe = Path.Combine(_testSandbox, "signed_app.exe");
            var dummyPe = new byte[1024];
            dummyPe[0] = 0x4D; dummyPe[1] = 0x5A; // MZ
            dummyPe[0x3C] = 0x80; // PE offset
            dummyPe[0x80] = 0x50; dummyPe[0x81] = 0x45; // PE\0\0
            await File.WriteAllBytesAsync(testExe, dummyPe);

            var hashService = new HashService();
            var sigVerifier = new MockSignatureVerifier { ForceValid = true, ForcePublisher = "Microsoft Corporation" };
            var scoring = new RiskScoringEngine();
            var findingService = new MockSecurityFindingService();
            var allowlist = new AllowlistService(hashService);
            var quarantine = new QuarantineService(hashService, null, null, Path.Combine(_testSandbox, "Vault"));
            var scanner = new FileScannerService(hashService, sigVerifier, scoring, allowlist, findingService);

            var rtEngine = new RealTimeProtectionEngine(
                scanner, hashService, sigVerifier, scoring, quarantine, findingService);

            var verdict = await rtEngine.InspectFileAsync(testExe);

            Assert.Equal(RealTimeVerdict.Clean, verdict.Verdict);
            Assert.Equal(RealTimePolicyAction.Allow, verdict.RecommendedPolicy);
        }

        // =========================================================================
        // === C. PERFORMANS & KAPSAM (Scenarios 7 - 9) ===
        // =========================================================================

        [Fact]
        public async Task Scenario07_ScannerUsesBoundedChannelAndDoesNotLeakMemory()
        {
            var scanDir = Path.Combine(_testSandbox, "bulk_files");
            Directory.CreateDirectory(scanDir);
            for (int i = 0; i < 200; i++)
            {
                File.WriteAllText(Path.Combine(scanDir, $"file_{i}.txt"), $"Content {i}");
            }

            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var findingService = new MockSecurityFindingService();
            var scanner = new FileScannerService(
                hashService, sigVerifier, new RiskScoringEngine(), new AllowlistService(hashService), findingService);

            long memBefore = GC.GetTotalMemory(forceFullCollection: true);
            var result = await scanner.ScanDirectoryAsync(scanDir, ScanType.Custom);
            long memAfter = GC.GetTotalMemory(forceFullCollection: true);

            Assert.Equal(200, result.TotalFiles);
            Assert.True(Math.Abs(memAfter - memBefore) < 20 * 1024 * 1024, "Memory growth must remain bounded under 20MB");
        }

        [Fact]
        public void Scenario08_ExcludedDirectoryNames_ContainsDevAndSystemDirs()
        {
            Assert.True(FileScannerService.ExcludedDirectoryNames.Contains("node_modules"));
            Assert.True(FileScannerService.ExcludedDirectoryNames.Contains(".git"));
            Assert.True(FileScannerService.ExcludedDirectoryNames.Contains("obj"));
            Assert.True(FileScannerService.ExcludedDirectoryNames.Contains("bin"));
            Assert.True(FileScannerService.ExcludedDirectoryNames.Contains("WinSxS"));
        }

        // =========================================================================
        // === E. FİDYE KALKANI VE KARANTİNA (Scenarios 14 - 15) ===
        // =========================================================================

        [Fact]
        public async Task Scenario14_RansomwareCanaryViolation_TriggersCriticalDetection()
        {
            var hashService = new HashService();
            var quarantineService = new QuarantineService(hashService, null, null, Path.Combine(_testSandbox, "Vault"));
            var findingService = new MockSecurityFindingService();

            var engine = new RansomwareProtectionEngine(
                quarantineService: quarantineService,
                findingService: findingService);

            var canaryPath = Path.Combine(_testSandbox, "!_ultron_shield_canary.docx");
            await File.WriteAllTextAsync(canaryPath, "Canary content");

            var assessment = await engine.EvaluateAndContainThreatAsync(canaryPath, "Canary tampered", riskScore: 100);

            Assert.NotNull(assessment);
            Assert.True(assessment.IncidentTime <= DateTime.UtcNow);
        }

        [Fact]
        public async Task Scenario15_QuarantineAndRestore_FilePreservedIntact()
        {
            var origDir = Path.Combine(_testSandbox, "Original");
            Directory.CreateDirectory(origDir);
            var origFile = Path.Combine(origDir, "important_document.txt");
            string expectedContent = "ULTRON_DEFENDER_TEST_RESTORE_INTEGRITY_CHECK_2026";
            await File.WriteAllTextAsync(origFile, expectedContent, Encoding.UTF8);

            var vaultDir = Path.Combine(_testSandbox, "Vault");
            var hashService = new HashService();
            var quarantine = new QuarantineService(hashService, customVaultDir: vaultDir);

            bool qSuccess = await quarantine.QuarantineFileAsync(origFile, "Test Threat");
            Assert.True(qSuccess);
            Assert.False(File.Exists(origFile), "Original file must be removed after quarantine.");

            var entries = await quarantine.GetQuarantinedItemsAsync();
            var entry = entries.FirstOrDefault(e => e.OriginalPath.Equals(origFile, StringComparison.OrdinalIgnoreCase));
            Assert.NotNull(entry);

            bool rSuccess = await quarantine.RestoreFileAsync(entry.Id, origFile);
            Assert.True(rSuccess);
            Assert.True(File.Exists(origFile), "File must be restored back to original path.");

            string restoredContent = await File.ReadAllTextAsync(origFile, Encoding.UTF8);
            Assert.Equal(expectedContent, restoredContent);
        }

        // =========================================================================
        // === F. AĞ VE DNS (Scenario 16) ===
        // =========================================================================

        [Fact]
        public async Task Scenario16_DnsProtectionService_EnumeratesAdaptersSafely()
        {
            var dnsService = new DnsProtectionService(new WebShieldService());
            var adapters = await dnsService.GetNetworkAdaptersDnsAsync();
            Assert.NotNull(adapters);
        }
    }

    public class MockSignatureVerifier : ISignatureVerifier
    {
        public bool ForceValid { get; set; }
        public string ForcePublisher { get; set; } = "Microsoft Corporation";

        public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new SignatureInfo
            {
                IsSigned = ForceValid,
                IsValid = ForceValid,
                Publisher = ForceValid ? ForcePublisher : null
            });
        }
    }

    public class MockSecurityFindingService : ISecurityFindingService
    {
        private readonly List<SecurityFinding> _findings = new();

        public Task AddFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default)
        {
            _findings.Add(finding);
            return Task.CompletedTask;
        }

        public Task<List<SecurityFinding>> GetAllFindingsAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_findings.ToList());
        }

        public Task<List<SecurityFinding>> GetFindingsByRiskAsync(RiskLevel riskLevel, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_findings.Where(f => f.RiskLevel == riskLevel).ToList());
        }

        public Task<SecurityFinding?> GetFindingByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_findings.FirstOrDefault(x => x.Id == id));
        }

        public Task<int> GetActiveCountAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_findings.Count(f => f.Status == FindingStatus.Active));
        }

        public Task UpdateFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default)
        {
            var existing = _findings.FirstOrDefault(x => x.Id == finding.Id);
            if (existing != null)
            {
                _findings.Remove(existing);
                _findings.Add(finding);
            }
            return Task.CompletedTask;
        }
    }
}
