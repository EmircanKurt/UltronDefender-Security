using System;
using System.Runtime.InteropServices;

namespace AegisPC.Performance.Monitoring
{
    /// <summary>
    /// Measures total and available physical and virtual memory using GlobalMemoryStatusEx Win32 API.
    /// </summary>
    public class MemoryMonitor
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        public (long totalBytes, long usedBytes, long freeBytes, double usagePercent) GetMemoryMetrics()
        {
            var stat = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (!GlobalMemoryStatusEx(ref stat))
            {
                // Fallback to GC/Environment if Win32 API fails
                long total = 16L * 1024 * 1024 * 1024;
                long used = GC.GetTotalMemory(false);
                return (total, used, total - used, (double)used / total * 100);
            }

            long totalPhys = (long)stat.ullTotalPhys;
            long availPhys = (long)stat.ullAvailPhys;
            long usedPhys = totalPhys - availPhys;
            double percent = totalPhys > 0 ? ((double)usedPhys / totalPhys) * 100.0 : 0.0;

            return (totalPhys, usedPhys, availPhys, Math.Round(percent, 1));
        }
    }
}
