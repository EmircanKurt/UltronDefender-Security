using System;
using AegisPC.Contracts.SelfProtection;
using AegisPC.Security.SelfProtection;
using Xunit;

namespace AegisPC.Tests
{
    public class SelfProtectionTests
    {
        [Fact]
        public void Test_SelfProtection_ReturnsActiveStatus()
        {
            var engine = new SelfProtectionEngine();
            var status = engine.GetStatus();

            Assert.True(status.IsProcessProtectionActive);
            Assert.True(status.IsServiceAclHardened);
            Assert.True(status.IsRegistryLockActive);
            Assert.True(status.IsVaultFileProtected);
            Assert.Equal(0, status.BlockedTamperAttemptsCount);
        }

        [Fact]
        public void Test_SelfProtection_BlocksAndLogsTamperAttempt()
        {
            var engine = new SelfProtectionEngine();
            TamperAttemptEvent? captured = null;
            engine.OnTamperAttemptBlocked += evt => captured = evt;

            bool blocked = engine.RecordAndBlockTamperAttempt(
                TamperTargetType.ProcessKill,
                6666,
                "malicious_killer.exe",
                "AegisPC.Service.exe",
                "Attempted OpenProcess with PROCESS_TERMINATE rights");

            Assert.True(blocked);
            Assert.NotNull(captured);
            Assert.Equal(TamperTargetType.ProcessKill, captured.TargetType);
            Assert.Equal(6666, captured.SourcePid);
            Assert.True(captured.WasBlocked);

            var status = engine.GetStatus();
            Assert.Equal(1, status.BlockedTamperAttemptsCount);
        }
    }
}
