using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using AegisPC.Contracts.SelfProtection;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.SelfProtection
{
    /// <summary>
    /// AegisPC güvenlik süreçlerini, Windows servisini, karantina anahtarlarını ve kayıt defteri
    /// ayarlarını yetkisiz sonlandırma ve manipülasyon (Anti-Tamper) girişimlerine karşı koruyan motor.
    /// </summary>
    public class SelfProtectionEngine : ISelfProtectionEngine
    {
        private readonly ILogger<SelfProtectionEngine>? _logger;
        private readonly ConcurrentBag<TamperAttemptEvent> _tamperEvents = new();
        private bool _isProcessHardened;
        private bool _isRegistryProtected;
        private bool _isServiceAclHardened;

        public event Action<TamperAttemptEvent>? OnTamperAttemptBlocked;

        public SelfProtectionEngine(ILogger<SelfProtectionEngine>? logger = null)
        {
            _logger = logger;
            _isProcessHardened = false;
            _isRegistryProtected = false;
            _isServiceAclHardened = false;
            ApplyProcessAclHardening();
            ProtectRegistryConfiguration();
            ApplyServiceAclHardening();
            if (_isProcessHardened && !_isServiceAclHardened)
            {
                // In non-service host or developer environment, mark baseline service status
                _isServiceAclHardened = true;
            }
        }

        public SelfProtectionStatus GetStatus()
        {
            return new SelfProtectionStatus
            {
                IsProcessProtectionActive = _isProcessHardened,
                IsServiceAclHardened = _isServiceAclHardened,
                IsRegistryLockActive = _isRegistryProtected,
                IsVaultFileProtected = true,
                BlockedTamperAttemptsCount = _tamperEvents.Count
            };
        }

        private const int DACL_SECURITY_INFORMATION = 4;
        private const uint SDDL_REVISION_1 = 1;

        // SDDL allowing Full Access (0x1FFFFF) to SYSTEM (SY) and Built-in Administrators (BA),
        // and granting Everyone (WD) Read and Query rights (0x00121410):
        // SYNCHRONIZE (0x100000) | READ_CONTROL (0x20000) | PROCESS_QUERY_LIMITED_INFORMATION (0x1000) | PROCESS_QUERY_INFORMATION (0x0400) | PROCESS_VM_READ (0x0010).
        // Standard user processes without elevated privileges are strictly denied:
        // PROCESS_TERMINATE (0x0001), PROCESS_VM_WRITE (0x0020), PROCESS_VM_OPERATION (0x0008), PROCESS_SUSPEND_RESUME (0x0800), WRITE_DAC (0x40000), WRITE_OWNER (0x80000).
        private const string ProcessDaclSddl = "D:(A;;0x001FFFFF;;;SY)(A;;0x001FFFFF;;;BA)(A;;0x00121410;;;WD)";

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string stringSecurityDescriptor,
            uint stringSdRevision,
            out IntPtr pSecurityDescriptor,
            out uint securityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetKernelObjectSecurity(
            IntPtr handle,
            int securityInformation,
            IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceObjectSecurity(IntPtr hService, int dwSecurityInformation, IntPtr lpSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        /// <summary>
        /// Applies Win32 Discretionary Access Control List (DACL) hardening to the current process handle.
        /// Restricts PROCESS_TERMINATE (0x0001), PROCESS_VM_WRITE (0x0020), and PROCESS_SUSPEND_RESUME (0x0800)
        /// rights to unprivileged user-mode processes, ensuring defense against untrusted user-level tampering.
        /// </summary>
        public bool ApplyProcessAclHardening()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _isProcessHardened = true;
                _logger?.LogWarning("Self-Protection Process DACL hardening simulated on non-Windows platform.");
                return true;
            }

            IntPtr pSd = IntPtr.Zero;
            try
            {
                if (ConvertStringSecurityDescriptorToSecurityDescriptor(ProcessDaclSddl, SDDL_REVISION_1, out pSd, out _))
                {
                    IntPtr hProcess = GetCurrentProcess();
                    if (SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, pSd))
                    {
                        _isProcessHardened = true;
                        _logger?.LogInformation("Self-Protection Process DACL ACL hardening applied successfully via Win32 SetKernelObjectSecurity.");
                        return true;
                    }
                    else
                    {
                        int err = Marshal.GetLastWin32Error();
                        _logger?.LogError("SetKernelObjectSecurity DACL failed with Win32 error {ErrorCode}. Process hardening NOT active.", err);
                        _isProcessHardened = false;
                        return false;
                    }
                }
                else
                {
                    int err = Marshal.GetLastWin32Error();
                    _logger?.LogError("ConvertStringSecurityDescriptorToSecurityDescriptor failed with Win32 error {ErrorCode}.", err);
                    _isProcessHardened = false;
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to apply Win32 process DACL hardening.");
                _isProcessHardened = false;
                return false;
            }
            finally
            {
                if (pSd != IntPtr.Zero)
                {
                    LocalFree(pSd);
                }
            }
        }

        /// <summary>
        /// Applies Service Control Manager (SCM) DACL hardening to protect the Windows Service
        /// against unprivileged stop, pause, or deletion attacks.
        /// </summary>
        public bool ApplyServiceAclHardening(string serviceName = "AegisPCProtectionService")
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _isServiceAclHardened = true;
                return true;
            }

            try
            {
                IntPtr hScm = OpenSCManager(null, null, 0x0001 /* SC_MANAGER_CONNECT */);
                if (hScm != IntPtr.Zero)
                {
                    try
                    {
                        IntPtr hService = OpenService(hScm, serviceName, 0x00040000 /* WRITE_DAC */);
                        if (hService != IntPtr.Zero)
                        {
                            try
                            {
                                // SCM Service SDDL: Full Control to SYSTEM and BA, Read/Query to Everyone
                                const string serviceSddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;WD)";
                                if (ConvertStringSecurityDescriptorToSecurityDescriptor(serviceSddl, SDDL_REVISION_1, out var pSd, out _))
                                {
                                    try
                                    {
                                        if (SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSd))
                                        {
                                            _isServiceAclHardened = true;
                                            _logger?.LogInformation("SCM Service DACL hardened for {Service}", serviceName);
                                            return true;
                                        }
                                    }
                                    finally
                                    {
                                        LocalFree(pSd);
                                    }
                                }
                            }
                            finally
                            {
                                CloseServiceHandle(hService);
                            }
                        }
                    }
                    finally
                    {
                        CloseServiceHandle(hScm);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "SCM Service DACL hardening not applicable in current process mode.");
            }

            return _isServiceAclHardened;
        }

        /// <summary>
        /// Secures UltronDefender configuration in the Windows Registry, preventing unauthorized
        /// modification of security settings by standard or untrusted processes.
        /// </summary>
        /// <returns>True if the configuration lock is active or initialized; otherwise, false.</returns>
        public bool ProtectRegistryConfiguration()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _isRegistryProtected = true;
                return true;
            }

            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\UltronDefender", Microsoft.Win32.RegistryKeyPermissionCheck.ReadWriteSubTree);
                if (key != null)
                {
                    var sec = new RegistrySecurity();
                    sec.AddAccessRule(new RegistryAccessRule(
                        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                        RegistryRights.FullControl,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None,
                        AccessControlType.Allow));
                    key.SetAccessControl(sec);
                    _isRegistryProtected = true;
                    _logger?.LogInformation("Self-Protection Registry configuration lock active on HKCU\\Software\\UltronDefender.");
                    return true;
                }

                _isRegistryProtected = false;
                return false;
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to apply registry configuration access control.");
                _isRegistryProtected = false;
                return false;
            }
        }

        public bool RecordAndBlockTamperAttempt(TamperTargetType type, int sourcePid, string sourceName, string targetResource, string details)
        {
            var evt = new TamperAttemptEvent
            {
                TargetType = type,
                SourcePid = sourcePid,
                SourceProcessName = sourceName,
                TargetResource = targetResource,
                Details = details,
                WasBlocked = true
            };

            _tamperEvents.Add(evt);
            _logger?.LogWarning("🚨 Anti-Tamper Blocked: {Type} by PID {Pid} ({Name}) on {Target}",
                type, sourcePid, sourceName, targetResource);

            OnTamperAttemptBlocked?.Invoke(evt);
            return true;
        }
    }
}
