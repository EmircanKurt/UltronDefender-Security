using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Logging;

namespace AegisPC.Infrastructure.Platform
{
    /// <summary>
    /// Reads battery, desktop interference, and physical-disk busy time without allocating synthetic benchmark workloads.
    /// Unknown measurements remain distinct from measured idleness; timed scans may elect a low-impact profile,
    /// while opportunistic idle work must defer when the interactive desktop cannot be inspected.
    /// </summary>
    public class WindowsScanSchedulerEnvironmentProvider : IScanSchedulerEnvironmentProvider, IScanSchedulerDesktopStatusProvider, IDisposable
    {
        private readonly ILogger<WindowsScanSchedulerEnvironmentProvider>? _logger;
        private readonly object _counterLock = new();
        private IntPtr _diskQuery;
        private IntPtr _diskCounter;
        private long _lastDiskSampleTimestamp;
        private double _lastDiskBusyPercentage = 100;
        private bool _diskCounterFailed;
        private bool _disposed;

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_POWER_STATUS
        {
            public byte ACLineStatus; // 0 = Offline (Battery), 1 = Online (AC), 255 = Unknown
            public byte BatteryFlag;
            public byte BatteryLifePercent;
            public byte SystemStatusFlag;
            public int BatteryLifeTime;
            public int BatteryFullLifeTime;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS lpSystemPowerStatus);

        private enum QUERY_USER_NOTIFICATION_STATE
        {
            QUNS_NOT_PRESENT = 1,
            QUNS_BUSY = 2,
            QUNS_RUNNING_D3D_FULL_SCREEN = 3,
            QUNS_PRESENTATION_MODE = 4,
            QUNS_ACCEPTS_NOTIFICATIONS = 5,
            QUNS_QUIET_TIME = 6,
            QUNS_APP = 7
        }

        [DllImport("shell32.dll")]
        private static extern int SHQueryUserNotificationState(out QUERY_USER_NOTIFICATION_STATE pquns);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern IntPtr MonitorFromWindow(IntPtr window, uint flags);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetMonitorInfoW(IntPtr monitor, ref MONITORINFO info);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MONITORINFO
        {
            public int Size;
            public RECT Monitor;
            public RECT Work;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PDH_FMT_COUNTERVALUE
        {
            public uint Status;
            public double Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public int SessionId;
            public IntPtr StationName;
            public int State;
        }

        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        private static extern uint PdhOpenQueryW(IntPtr source, UIntPtr userData, out IntPtr query);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        private static extern uint PdhAddEnglishCounterW(IntPtr query, string path, UIntPtr userData, out IntPtr counter);
        [DllImport("pdh.dll")]
        private static extern uint PdhCollectQueryData(IntPtr query);
        [DllImport("pdh.dll")]
        private static extern uint PdhGetFormattedCounterValue(IntPtr counter, uint format, out uint type, out PDH_FMT_COUNTERVALUE value);
        [DllImport("pdh.dll")]
        private static extern uint PdhCloseQuery(IntPtr query);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr buffer);

        /// <summary>Primes a locale-independent native PDH idle-time counter; unsupported measurements remain busy/unknown.</summary>
        public WindowsScanSchedulerEnvironmentProvider(ILogger<WindowsScanSchedulerEnvironmentProvider>? logger = null)
        {
            _logger = logger;
            InitializeDiskCounter();
        }

        private void InitializeDiskCounter()
        {
            try
            {
                _diskCounterFailed = true;
                if (!OperatingSystem.IsWindows()) return;
                uint status = PdhOpenQueryW(IntPtr.Zero, UIntPtr.Zero, out _diskQuery);
                if (status == 0)
                    status = PdhAddEnglishCounterW(_diskQuery, @"\PhysicalDisk(_Total)\% Idle Time", UIntPtr.Zero, out _diskCounter);
                if (status == 0) status = PdhCollectQueryData(_diskQuery);
                _diskCounterFailed = status != 0;
                _lastDiskSampleTimestamp = Stopwatch.GetTimestamp();
                if (_diskCounterFailed) _logger?.LogWarning("Physical-disk telemetry could not be primed. PDH status: {Status}.", status);
            }
            catch (Exception ex)
            {
                _diskCounterFailed = true;
                _logger?.LogWarning(ex, "Physical-disk telemetry initialization failed; automatic scanning is deferred.");
            }
        }

        /// <summary>Returns true for battery or unknown power state so unattended scans do not assume unavailable AC power.</summary>
        public bool IsRunningOnBattery()
        {
            try
            {
                if (OperatingSystem.IsWindows() && GetSystemPowerStatus(out var status))
                {
                    return status.ACLineStatus != 1;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "System power status query failed.");
            }
            return true;
        }

        /// <summary>
        /// Conservatively reports unknown desktop observations as interference for legacy and idle callers.
        /// Call the tri-state capability to distinguish an unavailable observation from an observed fullscreen application.
        /// </summary>
        public bool IsFullscreenOrGameActive() => GetFullscreenOrGameActivity() != false;

        /// <summary>
        /// Returns observed fullscreen interference, measured absence, or null for unavailable desktop information.
        /// Session-zero calls cannot inspect another user's unlocked desktop; they report null rather than a fictitious game.
        /// </summary>
        public bool? GetFullscreenOrGameActivity()
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    using var currentProcess = Process.GetCurrentProcess();
                    if (currentProcess.SessionId == 0) return GetServiceDesktopActivity();
                    // 1. Windows Shell32 API: Fullscreen D3D / Presentation Mode
                    if (SHQueryUserNotificationState(out var state) == 0)
                    {
                        if (state == QUERY_USER_NOTIFICATION_STATE.QUNS_RUNNING_D3D_FULL_SCREEN ||
                            state == QUERY_USER_NOTIFICATION_STATE.QUNS_PRESENTATION_MODE ||
                            state == QUERY_USER_NOTIFICATION_STATE.QUNS_BUSY || state == QUERY_USER_NOTIFICATION_STATE.QUNS_APP)
                        {
                            return true;
                        }
                    }

                    // 2. Yedek: Ön plandaki pencerenin ekran boyutunu kaplayıp kaplamadığını denetle
                    var fgHwnd = GetForegroundWindow();
                    if (fgHwnd != IntPtr.Zero && GetWindowRect(fgHwnd, out var rect))
                    {
                        var monitor = new MONITORINFO { Size = Marshal.SizeOf<MONITORINFO>() };
                        if (!GetMonitorInfoW(MonitorFromWindow(fgHwnd, 2), ref monitor)) return null;
                        if (rect.Left <= monitor.Monitor.Left && rect.Top <= monitor.Monitor.Top &&
                            rect.Right >= monitor.Monitor.Right && rect.Bottom >= monitor.Monitor.Bottom)
                        {
                            // Tam ekran pencere aktif
                            return true;
                        }
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Fullscreen interference query failed; desktop activity remains unknown.");
            }
            return null;
        }

        /// <summary>Returns a cached native disk busy-time percentage; unprimed, invalid, or failed readings return 100.</summary>
        public double GetDiskActivityPercentage()
        {
            lock (_counterLock)
            {
                if (_disposed || _diskCounterFailed || _diskCounter == IntPtr.Zero) return 100;
                if (Stopwatch.GetElapsedTime(_lastDiskSampleTimestamp) < TimeSpan.FromSeconds(2)) return _lastDiskBusyPercentage;
                _lastDiskSampleTimestamp = Stopwatch.GetTimestamp();
                try
                {
                    uint status = PdhCollectQueryData(_diskQuery);
                    PDH_FMT_COUNTERVALUE value = default;
                    if (status == 0) status = PdhGetFormattedCounterValue(_diskCounter, 0x200, out _, out value);
                    bool valid = status == 0 && value.Status <= 1;
                    _lastDiskBusyPercentage = NormalizeDiskActivity(valid, value.Value);
                    if (!valid) _logger?.LogDebug("Disk activity query failed. PDH status: {Status}, counter status: {CounterStatus}.", status, value.Status);
                }
                catch (Exception ex)
                {
                    _lastDiskBusyPercentage = 100;
                    _logger?.LogDebug(ex, "Physical-disk activity query failed; automatic work is deferred.");
                }
                return _lastDiskBusyPercentage;
            }
        }

        /// <summary>Converts a valid native idle percentage to busy time; invalid data cannot authorize automatic scanning.</summary>
        public static double NormalizeDiskActivity(bool measurementAvailable, double idlePercentage) =>
            measurementAvailable && double.IsFinite(idlePercentage) && idlePercentage is >= 0 and <= 100
                ? 100 - idlePercentage : 100;

        private bool? GetServiceDesktopActivity()
        {
            IntPtr sessions = IntPtr.Zero;
            try
            {
                if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out sessions, out int count)) return null;
                if (count < 0 || count > 4096 || (count > 0 && sessions == IntPtr.Zero)) return null;
                int size = Marshal.SizeOf<WTS_SESSION_INFO>();
                for (int i = 0; i < count; i++)
                {
                    var session = Marshal.PtrToStructure<WTS_SESSION_INFO>(IntPtr.Add(sessions, i * size));
                    if (session.SessionId == 0 || session.State != 0) continue;
                    IntPtr buffer = IntPtr.Zero;
                    try
                    {
                        if (!WTSQuerySessionInformationW(IntPtr.Zero, session.SessionId, 25, out buffer, out int bytes) ||
                            buffer == IntPtr.Zero || bytes < 20 || Marshal.ReadInt32(buffer) != 1) return null;
                        // WTSINFOEX.Level is followed by 8-byte-aligned Data; SessionFlags is at offset 16.
                        // Windows 10/11 LOCK = 0. Unknown and unlocked sessions cannot be inspected from session zero.
                        if (Marshal.ReadInt32(buffer, 16) != 0) return null;
                    }
                    finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
                }
                return false;
            }
            finally { if (sessions != IntPtr.Zero) WTSFreeMemory(sessions); }
        }

        /// <summary>Releases the native PDH query; subsequent samples remain unavailable/busy.</summary>
        public void Dispose()
        {
            lock (_counterLock)
            {
                if (_disposed) return;
                _disposed = true;
                if (_diskQuery != IntPtr.Zero)
                {
                    uint status = PdhCloseQuery(_diskQuery);
                    if (status != 0) _logger?.LogDebug("PDH query disposal returned status {Status}.", status);
                    _diskQuery = IntPtr.Zero;
                    _diskCounter = IntPtr.Zero;
                }
            }
        }
    }
}
