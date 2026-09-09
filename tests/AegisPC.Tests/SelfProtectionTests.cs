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

        [Fact]
        public void Test_SelfProtection_ApplyProcessAclHardening_Succeeds()
        {
            var engine = new SelfProtectionEngine();
            bool aclSuccess = engine.ApplyProcessAclHardening();
            bool regSuccess = engine.ProtectRegistryConfiguration();

            Assert.True(aclSuccess);
            Assert.True(regSuccess);

            var status = engine.GetStatus();
            Assert.True(status.IsProcessProtectionActive);
            Assert.True(status.IsRegistryLockActive);
        }

        [Fact]
        public void Test_SelfProtection_VerifiesActualOsSecurityDescriptorAndDacl()
        {
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            {
                return;
            }

            var engine = new SelfProtectionEngine();
            bool applied = engine.ApplyProcessAclHardening();
            Assert.True(applied);

            // Directly query OS-level security descriptor of the current process via Win32 advapi32
            IntPtr hProcess = GetCurrentProcess();
            IntPtr pDacl;
            IntPtr pSd;

            uint ret = GetSecurityInfo(hProcess, 6 /* SE_KERNEL_OBJECT */, 4 /* DACL_SECURITY_INFORMATION */,
                IntPtr.Zero, IntPtr.Zero, out pDacl, IntPtr.Zero, out pSd);

            Assert.Equal(0u, ret);
            Assert.NotEqual(IntPtr.Zero, pSd);

            try
            {
                IntPtr pSddl;
                uint len;
                bool conv = ConvertSecurityDescriptorToStringSecurityDescriptor(
                    pSd, 1 /* SDDL_REVISION_1 */, 4 /* DACL_SECURITY_INFORMATION */, out pSddl, out len);

                Assert.True(conv);
                Assert.NotEqual(IntPtr.Zero, pSddl);

                try
                {
                    string sddl = System.Runtime.InteropServices.Marshal.PtrToStringUni(pSddl) ?? string.Empty;

                    // Verify that the actual OS DACL contains the restricted rights ACE for Everyone (WD)
                    // and Full Access for SYSTEM (SY) and Administrators (BA)
                    Assert.Contains("(A;;0x121410;;;WD)", sddl, StringComparison.OrdinalIgnoreCase);
                    Assert.Contains("(A;;0x1fffff;;;SY)", sddl, StringComparison.OrdinalIgnoreCase);
                    Assert.Contains("(A;;0x1fffff;;;BA)", sddl, StringComparison.OrdinalIgnoreCase);
                }
                finally
                {
                    LocalFree(pSddl);
                }
            }
            finally
            {
                LocalFree(pSd);
            }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(
            IntPtr handle,
            int objectType,
            int securityInformation,
            IntPtr pSidOwner,
            IntPtr pSidGroup,
            out IntPtr pDacl,
            IntPtr pSacl,
            out IntPtr pSecurityDescriptor);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr pSecurityDescriptor,
            uint requestedStringSdRevision,
            int securityInformation,
            out IntPtr stringSecurityDescriptor,
            out uint stringSecurityDescriptorLen);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);
    }
}
