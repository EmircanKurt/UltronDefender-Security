using System;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using AegisPC.Core.Constants;
using AegisPC.Core.Helpers;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Zararlı veya şüpheli süreçlerin anlık dondurulması (NtSuspendProcess) ve
    /// tüm alt süreç ağacıyla birlikte sonlandırılmasını yöneten yardımcı servis.
    /// </summary>
    public static class ProcessMitigationHelper
    {
        #region Native Win32 / NT API
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSuspendProcess(IntPtr processHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtResumeProcess(IntPtr processHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_SUSPEND_RESUME = 0x0800;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint PROCESS_TERMINATE = 0x0001;
        #endregion

        /// <summary>
        /// Belirtilen süreç kimliğini (PID) işletim sistemi düzeyinde açar ve NtSuspendProcess ile yürütmesini askıya alır.
        /// Başarılı olursa açık process handle'ını döndürür (işlem bitince SafeCloseHandle ile kapatılmalıdır).
        /// </summary>
        public static bool TrySuspendProcessById(int processId, out IntPtr processHandle)
        {
            processHandle = IntPtr.Zero;
            if (processId <= 4) return false;

            try
            {
                processHandle = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, false, processId);
                if (processHandle != IntPtr.Zero)
                {
                    int status = NtSuspendProcess(processHandle);
                    if (status == 0)
                    {
                        return true;
                    }

                    CloseHandle(processHandle);
                    processHandle = IntPtr.Zero;
                }
            }
            catch { }

            return false;
        }

        /// <summary>
        /// Askıya alınmış bir sürecin yürütmesini devam ettirir (Resume).
        /// Mevcut handle verilmişse onu kullanır; verilmemişse süreci açıp resume eder.
        /// </summary>
        public static bool TryResumeProcessById(int processId, IntPtr processHandle = default)
        {
            try
            {
                if (processHandle != IntPtr.Zero)
                {
                    return NtResumeProcess(processHandle) == 0;
                }

                if (processId <= 4) return false;

                IntPtr hProc = OpenProcess(PROCESS_SUSPEND_RESUME, false, processId);
                if (hProc != IntPtr.Zero)
                {
                    try
                    {
                        return NtResumeProcess(hProc) == 0;
                    }
                    finally
                    {
                        CloseHandle(hProc);
                    }
                }
            }
            catch { }

            return false;
        }

        /// <summary>
        /// Bir Win32 tanıtıcısını (Handle) güvenli şekilde serbest bırakır.
        /// </summary>
        public static void SafeCloseHandle(IntPtr handle)
        {
            try
            {
                if (handle != IntPtr.Zero)
                {
                    CloseHandle(handle);
                }
            }
            catch { }
        }

        /// <summary>
        /// Bir sürecin CPU yürütmesini NT çekirdek seviyesinde askıya alarak dondurur.
        /// Fidye yazılımlarının şifreleme ve dosya tahribatını milisaniyeler içinde durdurur.
        /// </summary>
        /// <param name="processHandle">Hedef sürecin işletim sistemi tanıtıcısı (Handle).</param>
        /// <returns>İşlem başarılıysa true, aksi halde false.</returns>
        public static bool TrySuspendProcess(IntPtr processHandle)
        {
            try
            {
                if (processHandle != IntPtr.Zero)
                {
                    return NtSuspendProcess(processHandle) == 0;
                }
            }
            catch { }
            return false;
        }

        /// <summary>
        /// Askıya alınmış bir sürecin yürütmesini devam ettirir.
        /// </summary>
        /// <param name="processHandle">Hedef sürecin işletim sistemi tanıtıcısı (Handle).</param>
        /// <returns>İşlem başarılıysa true, aksi halde false.</returns>
        public static bool TryResumeProcess(IntPtr processHandle)
        {
            try
            {
                if (processHandle != IntPtr.Zero)
                {
                    return NtResumeProcess(processHandle) == 0;
                }
            }
            catch { }
            return false;
        }

        /// <summary>
        /// Belirtilen dosya yolu veya süreç kimliğiyle ilişkili çalışan zararlı süreci tespit eder,
        /// önce anında dondurur (suspend) ve ardından süreç ağacıyla birlikte sonlandırır.
        /// </summary>
        /// <param name="targetFilePath">Zararlı olduğu belirlenen dosyanın tam yolu.</param>
        /// <param name="processId">Hedef süreç kimliği (varsa).</param>
        /// <param name="logger">Hata ve bilgi günlüğü için ILogger nesnesi.</param>
        /// <returns>Sonlandırılan sürecin ID ve adı; süreç bulunamadıysa (0, "").</returns>
        public static (int TerminatedPid, string TerminatedProcessName) ContainAndTerminateTargetProcess(
            string targetFilePath, 
            int processId, 
            ILogger? logger = null)
        {
            int terminatedPid = 0;
            string terminatedProcName = string.Empty;

            try
            {
                var runningProcesses = Process.GetProcesses();
                foreach (var proc in runningProcesses)
                {
                    using (proc)
                    {
                        try
                        {
                            if (proc.Id <= 4) continue;
                            if (CriticalProcesses.IsCriticalProcess(proc.ProcessName)) continue;

                            bool isTargetProcess = false;
                            try
                            {
                                if (string.Equals(proc.MainModule?.FileName, targetFilePath, StringComparison.OrdinalIgnoreCase))
                                {
                                    isTargetProcess = true;
                                }
                            }
                            catch { }

                            if (!isTargetProcess && processId > 0 && proc.Id == processId)
                            {
                                isTargetProcess = true;
                            }

                            if (isTargetProcess)
                            {
                                terminatedPid = proc.Id;
                                terminatedProcName = proc.ProcessName;

                                // 1. Önce süreci anında dondur (Ransomware şifreleme ve disk tahribatını milisaniyede durdurur)
                                try
                                {
                                    NtSuspendProcess(proc.Handle);
                                }
                                catch { }

                                // 2. Ardından tüm süreç ağacıyla birlikte yok et
                                KillProcessTree(terminatedPid, logger);
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            logger?.LogTrace(ex, "Failed inspecting process during active containment");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger?.LogTrace(ex, "Active process containment failed for {Path}", targetFilePath);
            }

            return (terminatedPid, terminatedProcName);
        }

        /// <summary>
        /// WMI Win32_Process tablosunu sorgulayarak bir sürecin tüm alt süreçlerini (çocuklarını)
        /// özyinelemeli olarak bulur ve ağaç halinde sonlandırır.
        /// </summary>
        /// <param name="rootPid">Kök süreç kimliği.</param>
        /// <param name="logger">Hata ve bilgi günlüğü için ILogger nesnesi.</param>
        public static void KillProcessTree(int rootPid, ILogger? logger = null)
        {
            if (rootPid <= 4) return;

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ProcessId FROM Win32_Process WHERE ParentProcessId={rootPid}");
                using var moc = searcher.Get();
                foreach (var mo in moc)
                {
                    using (mo)
                    {
                        var childPid = Convert.ToInt32(mo["ProcessId"]);
                        KillProcessTree(childPid, logger);
                    }
                }
            }
            catch { }

            try
            {
                using var proc = Process.GetProcessById(rootPid);
                if (!proc.HasExited && !CriticalProcesses.IsCriticalProcess(proc.ProcessName))
                {
                    proc.Kill(entireProcessTree: true);
                }
            }
            catch (ArgumentException) { }
            catch (Exception ex)
            {
                logger?.LogTrace(ex, "Failed to terminate PID {Pid}", rootPid);
            }
        }
    }
}
