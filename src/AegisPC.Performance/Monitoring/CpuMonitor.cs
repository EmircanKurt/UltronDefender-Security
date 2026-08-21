using System;
using System.Runtime.InteropServices;

namespace AegisPC.Performance.Monitoring
{
    /// <summary>
    /// Measures total system CPU usage accurately with low overhead using GetSystemTimes Win32 API.
    /// </summary>
    public class CpuMonitor
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;

            public ulong Value => ((ulong)dwHighDateTime << 32) | dwLowDateTime;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetSystemTimes(out FILETIME lpIdleTime, out FILETIME lpKernelTime, out FILETIME lpUserTime);

        private ulong _previousIdleTime;
        private ulong _previousTotalTime;
        private bool _isFirstSample = true;

        public double GetCpuUsagePercentage()
        {
            if (!GetSystemTimes(out var idleTime, out var kernelTime, out var userTime))
            {
                return 0.0;
            }

            ulong currentIdle = idleTime.Value;
            ulong currentTotal = kernelTime.Value + userTime.Value;

            if (_isFirstSample)
            {
                _previousIdleTime = currentIdle;
                _previousTotalTime = currentTotal;
                _isFirstSample = false;
                return 0.0;
            }

            ulong deltaIdle = currentIdle - _previousIdleTime;
            ulong deltaTotal = currentTotal - _previousTotalTime;

            _previousIdleTime = currentIdle;
            _previousTotalTime = currentTotal;

            if (deltaTotal == 0) return 0.0;

            double cpuFraction = 1.0 - ((double)deltaIdle / deltaTotal);
            double percentage = cpuFraction * 100.0;

            return Math.Clamp(Math.Round(percentage, 1), 0.0, 100.0);
        }
    }
}
