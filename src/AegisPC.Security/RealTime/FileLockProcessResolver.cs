using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Windows Restart Manager API kullanarak bir dosyayı kilitleyen veya üzerinde açık tanıtıcısı (handle)
    /// bulunan süreçlerin PID ve başlatılma zamanlarını belirleyen yardımcı sınıf.
    /// </summary>
    public static class FileLockProcessResolver
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        private const int CchRmMaxAppName = 255;
        private const int CchRmMaxSvcName = 63;

        private enum RM_APP_TYPE
        {
            RmUnknownApp = 0,
            RmMainWindow = 1,
            RmOtherWindow = 2,
            RmService = 3,
            RmExplorer = 4,
            RmConsole = 5,
            RmCritical = 1000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CchRmMaxAppName + 1)]
            public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CchRmMaxSvcName + 1)]
            public string strServiceShortName;
            public RM_APP_TYPE ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bRestartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint pSessionHandle);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(
            uint pSessionHandle,
            uint nFiles,
            string[] rgsFilenames,
            uint nApplications,
            [In] RM_UNIQUE_PROCESS[]? rgApplications,
            uint nServices,
            [In] string[]? rgsServiceNames);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(
            uint dwSessionHandle,
            out uint pnProcInfoNeeded,
            ref uint pnProcInfo,
            [In, Out] RM_PROCESS_INFO[]? rgAffectedApps,
            ref uint lpdwRebootReasons);

        private const int ERROR_MORE_DATA = 234;

        /// <summary>
        /// Belirtilen dosya üzerinde açık tanıtıcısı bulunan çalışan süreçlerin PID listesini döndürür.
        /// </summary>
        public static List<int> FindLockingProcessIds(string filePath)
        {
            var result = new List<int>();
            if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return result;
            }

            string sessionKey = Guid.NewGuid().ToString();
            int res = RmStartSession(out uint handle, 0, sessionKey);
            if (res != 0) return result;

            try
            {
                string[] resources = { filePath };
                res = RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null);
                if (res != 0) return result;

                uint pnProcInfoNeeded = 0;
                uint pnProcInfo = 0;
                uint lpdwRebootReasons = 0;

                res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);
                if (res == ERROR_MORE_DATA && pnProcInfoNeeded > 0)
                {
                    var processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                    pnProcInfo = pnProcInfoNeeded;
                    res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                    if (res == 0)
                    {
                        for (int i = 0; i < pnProcInfo; i++)
                        {
                            int pid = processInfo[i].Process.dwProcessId;
                            if (pid > 4 && !result.Contains(pid))
                            {
                                result.Add(pid);
                            }
                        }
                    }
                }
            }
            catch
            {
                // Sessizce yutulabilir (Restart Manager istisnası ana akışı kesmemeli)
            }
            finally
            {
                RmEndSession(handle);
            }

            return result;
        }
    }
}
