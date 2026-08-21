using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Security.Safety;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class SafetyGuardTests : IDisposable
    {
        private readonly string _sandboxDir;
        private readonly CanonicalPathResolver _pathResolver;
        private readonly ProtectedPathGuard _protectedPathGuard;
        private readonly ReparsePointGuard _reparsePointGuard;
        private readonly TransactionalQuarantineEngine _quarantineEngine;

        public SafetyGuardTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "AegisSafetyTests_" + Guid.NewGuid().ToString("N"));
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
        public void Test_CanonicalPathResolver_ResolvesRelativeHopsAndSlashes()
        {
            var mixedPath = @"C:/Windows/System32/../System32/drivers/etc/hosts";
            var resolved = _pathResolver.Resolve(mixedPath);

            Assert.Equal(@"C:\Windows\System32\drivers\etc\hosts", resolved, ignoreCase: true);
            Assert.False(resolved.Contains('/'));
        }

        [Fact]
        public void Test_ProtectedPathGuard_ProtectsRegistryHives()
        {
            var samPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "config", "SAM");
            var eval = _protectedPathGuard.Evaluate(samPath);

            Assert.True(eval.IsProtected, "SAM hive must be protected.");
            Assert.True(eval.IsCriticalSystemCore, "SAM hive must be critical system core.");
            Assert.Equal(ProtectedPathCategory.WindowsRegistryHives, eval.Category);
        }

        [Fact]
        public void Test_ProtectedPathGuard_ProtectsCoreBinaries_Ntoskrnl_HalDll()
        {
            var ntoskrnl = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ntoskrnl.exe");
            var hal = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "hal.dll");

            var evalKernel = _protectedPathGuard.Evaluate(ntoskrnl);
            var evalHal = _protectedPathGuard.Evaluate(hal);

            Assert.True(evalKernel.IsProtected);
            Assert.True(evalKernel.IsCriticalSystemCore);
            Assert.Equal(ProtectedPathCategory.WindowsKernelAndBoot, evalKernel.Category);

            Assert.True(evalHal.IsProtected);
            Assert.True(evalHal.IsCriticalSystemCore);
        }

        [Fact]
        public void Test_ProtectedPathGuard_ProtectsWinSxSAndDrivers()
        {
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var winsxs = Path.Combine(winDir, "WinSxS", "sample_component.dll");
            var driver = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "ntfs.sys");

            var evalSxS = _protectedPathGuard.Evaluate(winsxs);
            var evalDriver = _protectedPathGuard.Evaluate(driver);

            Assert.True(evalSxS.IsProtected);
            Assert.Equal(ProtectedPathCategory.WindowsComponentStoreWinSxS, evalSxS.Category);

            Assert.True(evalDriver.IsProtected);
            Assert.True(evalDriver.IsCriticalSystemCore);
            Assert.Equal(ProtectedPathCategory.WindowsDrivers, evalDriver.Category);
        }

        [Fact]
        public void Test_ProtectedPathGuard_AllowsNormalUserFiles()
        {
            var userFile = Path.Combine(_sandboxDir, "harmless_user_app.exe");
            var eval = _protectedPathGuard.Evaluate(userFile);

            Assert.False(eval.IsProtected, "Normal user folder files must NOT be flagged as protected.");
            Assert.Equal(ProtectedPathCategory.None, eval.Category);
        }

        [Fact]
        public async Task Test_TransactionalQuarantine_PreFlightBlocksProtectedPath_NoDamage()
        {
            var samPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "config", "SAM");
            var request = new QuarantineRequest
            {
                TargetFilePath = samPath,
                ThreatReason = "Malicious.SimulatedThreat"
            };

            var result = await _quarantineEngine.ExecuteQuarantineAsync(request);

            Assert.False(result.Success, "Quarantine on protected system core MUST be rejected.");
            Assert.Equal(QuarantineTransactionStatus.AbortedProtectedPath, result.Status);
            Assert.Contains("Korumalı Sistem Dosyası", result.Message);
        }

        [Fact]
        public async Task Test_TransactionalQuarantine_EncryptedVaultContainer_AtomicCommitAndRestore()
        {
            var targetThreatFile = Path.Combine(_sandboxDir, "malicious_payload.exe");
            var payloadContent = "MALWARE_TEST_BINARY_PAYLOAD_FOR_TRANSACTIONAL_TEST_12345";
            await File.WriteAllTextAsync(targetThreatFile, payloadContent);

            var request = new QuarantineRequest
            {
                TargetFilePath = targetThreatFile,
                ThreatReason = "Trojan.SyntheticTestPayload",
                ForceKillHoldingProcesses = false,
                WipeOriginalPayloadBytes = true
            };

            // 1. Act: Execute Quarantine
            var result = await _quarantineEngine.ExecuteQuarantineAsync(request);

            // 2. Assert: Transaction Succeeded
            Assert.True(result.Success, "Quarantine transaction must succeed for unprivileged threat file.");
            Assert.Equal(QuarantineTransactionStatus.Committed, result.Status);
            Assert.True(result.QuarantineId > 0);
            Assert.True(File.Exists(result.VaultContainerPath), "Encrypted vault container file must exist.");
            Assert.False(File.Exists(targetThreatFile), "Original threat file MUST be removed from sandbox.");

            // Verify vault container contains encrypted data (not plaintext)
            var vaultBytes = await File.ReadAllBytesAsync(result.VaultContainerPath);
            var vaultHeader = Encoding.ASCII.GetString(vaultBytes, 0, 14);
            Assert.Equal("AEGIS_VAULT_V3", vaultHeader);
            Assert.DoesNotContain(payloadContent, Encoding.UTF8.GetString(vaultBytes));

            // 3. Act: Restore File
            var restoredFile = Path.Combine(_sandboxDir, "restored_payload.exe");
            var restoreResult = await _quarantineEngine.ExecuteRestoreAsync(result.QuarantineId, restoredFile);

            // 4. Assert: Restored file matches exact original plaintext
            Assert.True(restoreResult.Success, "Restore transaction must succeed.");
            Assert.True(File.Exists(restoredFile));
            var restoredContent = await File.ReadAllTextAsync(restoredFile);
            Assert.Equal(payloadContent, restoredContent);
        }
    }
}
