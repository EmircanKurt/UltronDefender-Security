using System;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Scheduler;

/// <summary>Provides measured input-idle duration; null means unattended work cannot safely be authorized.</summary>
public interface IIdleTimeProvider
{
    /// <summary>Returns the shortest idle duration across active user sessions, or null when a session query fails.</summary>
    TimeSpan? GetIdleDuration();
}

/// <summary>
/// Measures all active Windows sessions through WTS, including from the session-zero service.
/// GetLastInputInfo is not used because it sees only the calling session, not every user.
/// </summary>
public sealed class IdleDetector : IIdleTimeProvider
{
    private readonly ILogger<IdleDetector>? _logger;

    /// <summary>Creates a read-only native sampler; unavailable measurements defer unattended scans.</summary>
    public IdleDetector(ILogger<IdleDetector>? logger = null) => _logger = logger;

    /// <inheritdoc />
    public TimeSpan? GetIdleDuration()
    {
        if (!OperatingSystem.IsWindows()) return null;
        IntPtr sessions = IntPtr.Zero;
        try
        {
            if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out sessions, out int count))
            {
                _logger?.LogDebug("Session enumeration failed with Win32 error {Error}.", Marshal.GetLastWin32Error());
                return null;
            }
            if (count < 0 || count > 4096 || (count > 0 && sessions == IntPtr.Zero)) return null;
            TimeSpan shortest = TimeSpan.MaxValue;
            int size = Marshal.SizeOf<WtsSessionInfo>();
            for (int index = 0; index < count; index++)
            {
                var session = Marshal.PtrToStructure<WtsSessionInfo>(IntPtr.Add(sessions, index * size));
                if (session.SessionId == 0 || session.State != 0) continue; // WTSActive = 0.
                TimeSpan? duration = ReadSessionIdleDuration(session.SessionId);
                if (!duration.HasValue) return null;
                if (duration.Value < shortest) shortest = duration.Value;
            }
            // No active user means nobody can be interrupted; this is not a fabricated timer reading.
            return shortest;
        }
        catch (Exception ex) when (ex is ExternalException or ArgumentException or DllNotFoundException)
        {
            _logger?.LogWarning(ex, "Windows session idle measurement failed; unattended scanning is deferred.");
            return null;
        }
        finally
        {
            if (sessions != IntPtr.Zero) WTSFreeMemory(sessions);
        }
    }

    private TimeSpan? ReadSessionIdleDuration(int sessionId)
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, 25, out buffer, out int bytes) ||
                buffer == IntPtr.Zero || bytes < Marshal.SizeOf<WtsInfoEx>())
            {
                _logger?.LogDebug("Idle query for session {SessionId} failed with Win32 error {Error}.",
                    sessionId, Marshal.GetLastWin32Error());
                return null;
            }
            var info = Marshal.PtrToStructure<WtsInfoEx>(buffer);
            if (info.Level != 1 || info.Data.SessionId != sessionId || info.Data.SessionState != 0) return null;
            return CalculateSessionIdleDuration(info.Data.CurrentTime, info.Data.LastInputTime);
        }
        finally
        {
            if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
        }
    }

    /// <summary>Converts WTS UTC FILETIME ticks into elapsed time, rejecting absent or future input timestamps.</summary>
    public static TimeSpan? CalculateSessionIdleDuration(long currentTime, long lastInputTime) =>
        currentTime > 0 && lastInputTime > 0 && currentTime >= lastInputTime
            ? TimeSpan.FromTicks(currentTime - lastInputTime) : null;

    /// <summary>
    /// Computes session-local LASTINPUTINFO elapsed ticks with unsigned rollover handling.
    /// Implausible or future readings fail closed; this does not substitute for service-wide WTS sampling.
    /// </summary>
    public static TimeSpan? CalculateLocalIdleDuration(uint currentTicks, uint lastInputTicks)
    {
        uint elapsed = unchecked(currentTicks - lastInputTicks);
        return elapsed <= TimeSpan.FromDays(7).TotalMilliseconds ? TimeSpan.FromMilliseconds(elapsed) : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        public IntPtr StationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsInfoExLevel1
    {
        public int SessionId;
        public int SessionState;
        public int SessionFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string StationName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string UserName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] public string DomainName;
        public long LogonTime;
        public long ConnectTime;
        public long DisconnectTime;
        public long LastInputTime;
        public long CurrentTime;
        public uint IncomingBytes;
        public uint OutgoingBytes;
        public uint IncomingFrames;
        public uint OutgoingFrames;
        public uint IncomingCompressedBytes;
        public uint OutgoingCompressedBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsInfoEx
    {
        public uint Level;
        public WtsInfoExLevel1 Data;
    }

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr buffer);
}
