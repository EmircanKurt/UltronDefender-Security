using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using AegisPC.Security.Safety;
using AegisPC.Service.Update;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class SecurityHardeningRegressionTests : IDisposable
    {
        private readonly string _sandboxDir;
        private readonly CanonicalPathResolver _pathResolver;
        private readonly ProtectedPathGuard _protectedPathGuard;
        private readonly ReparsePointGuard _reparsePointGuard;
        private readonly TransactionalQuarantineEngine _quarantineEngine;

        public SecurityHardeningRegressionTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "Aegis_HardeningTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);

            _pathResolver = new CanonicalPathResolver();
            _protectedPathGuard = new ProtectedPathGuard(_pathResolver);
            _reparsePointGuard = new ReparsePointGuard(_pathResolver, _protectedPathGuard);
            _quarantineEngine = new TransactionalQuarantineEngine(
                _pathResolver,
                _protectedPathGuard,
                _reparsePointGuard,
                customVaultDir: Path.Combine(_sandboxDir, "Vault"));
        }

        public void Dispose()
        {
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
        public async Task AutoUpdate_UnsignedExecutable_ThrowsCryptographicException()
        {
            var updateService = new AutoUpdateService();
            string appDir = Path.Combine(_sandboxDir, "target_app");
            Directory.CreateDirectory(appDir);

            string unsignedExe = Path.Combine(_sandboxDir, "fake_update.exe");
            await File.WriteAllTextAsync(unsignedExe, "MZ_FAKE_PE_HEADER_NO_SIGNATURE");

            // Executables without valid Authenticode signature must throw CryptographicException on Apply
            await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            {
                await updateService.ApplyUpdateAsync(unsignedExe, appDir);
            });
        }

        [Fact]
        public async Task QuarantineRestore_ToProtectedSystemPath_IsBlocked()
        {
            // 1. Quarantining a benign test payload
            string threatFile = Path.Combine(_sandboxDir, "sample_threat.bin");
            await File.WriteAllTextAsync(threatFile, "MALWARE_PAYLOAD_TEST");

            var qResult = await _quarantineEngine.ExecuteQuarantineAsync(new QuarantineRequest
            {
                TargetFilePath = threatFile,
                ThreatReason = "Regression Test",
                ForceKillHoldingProcesses = false
            });

            Assert.True(qResult.Success);
            Assert.True(qResult.QuarantineId > 0);

            // 2. Attempting to restore to protected system path (Arbitrary File Overwrite LPE attack)
            string protectedTargetPath = @"C:\Windows\System32\calc.exe";
            var restoreResult = await _quarantineEngine.ExecuteRestoreAsync(qResult.QuarantineId, targetOverride: protectedTargetPath);

            Assert.False(restoreResult.Success, "Restoring to a protected system path MUST be blocked!");
            Assert.Contains("korunan sistem", restoreResult.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void TrustedSoftwarePolicy_ExactPublisherMatch_RejectsSpoofedPublishers()
        {
            // Exact word boundary matching tests
            Assert.False(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("CN=Microsoft Corporation, O=Microsoft"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Microsoft Corporation"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Google LLC"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Valve Corporation"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Python Software Foundation"));
            Assert.True(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("Docker Inc"));

            // Spoofed names must be rejected
            Assert.False(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("MicrosoftHackers"));
            Assert.False(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("FakeGoogleEvilCorp"));
            Assert.False(TrustedSoftwarePolicy.IsTrustedCommercialPublisher("ValvePhishingClub"));
        }

        [Fact]
        public void TrustedSoftwarePolicy_IsLegitimateInstallLocation_DoesNotTrustUserWritablePackageFolders()
        {
            Assert.True(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Program Files\Common Files\Provider\app.exe"));
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Users\User\AppData\Local\Programs\Python\python.exe"));
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"D:\Games\Steam\steamapps\common\game\game.exe"));
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Users\User\scoop\apps\git\current\bin\git.exe"));
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\ProgramData\chocolatey\lib\tool\tools\tool.exe"));

            // Arbitrary temp and download locations are NOT legitimate install locations
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Users\User\AppData\Local\Temp\evil.exe"));
            Assert.False(TrustedSoftwarePolicy.IsLegitimateInstallLocation(@"C:\Users\User\Downloads\setup.exe"));
        }

        [Fact]
        public async Task EtwPreExec_TempPathMicrosoftSigned_DoesNotGetFastPathWhitelist()
        {
            var fakeSigVerifier = new FakeMicrosoftSignatureVerifier();
            var riskScorer = new AegisPC.Security.Scanning.RiskScoringEngine();
            var detectionHub = AegisPC.Security.Detection.DetectionHubFactory.CreateDefault(signatureVerifier: fakeSigVerifier);

            var etwService = new EtwPreExecProtectionService(
                detectionHub,
                riskScorer,
                fakeSigVerifier);

            string tempExe = Path.Combine(Path.GetTempPath(), "certutil.exe");
            var decision = await etwService.EvaluateProcessAsync(1234, tempExe);

            // In Temp path, even if Microsoft signed, it MUST NOT get fast-path Whitelisted
            Assert.False(decision.Whitelisted, "Microsoft signed binaries in Temp/Downloads must NOT bypass pre-exec gating via fast-path!");
        }

        private class FakeMicrosoftSignatureVerifier : ISignatureVerifier
        {
            public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default)
            {
                return Task.FromResult(new SignatureInfo
                {
                    IsSigned = true,
                    IsValid = true,
                    Publisher = "Microsoft Corporation"
                });
            }

            public SignatureInfo VerifySignature(string filePath)
            {
                return new SignatureInfo
                {
                    IsSigned = true,
                    IsValid = true,
                    Publisher = "Microsoft Corporation"
                };
            }
        }
    }
}
