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
        #endregion

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
