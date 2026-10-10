using System.Runtime.InteropServices;
using AegisPC.Contracts.Protection;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Remote;

/// <summary>Reads only the physical console's WTS metadata; no global input hook, usernames or session actions are used.</summary>
public sealed class WindowsConsolePresenceObserver(ILogger<WindowsConsolePresenceObserver>? logger = null) : IConsolePresenceObserver
{
    /// <inheritdoc />
    public ConsolePresenceObservation Capture(DateTime utcNow)
    {
        if (!OperatingSystem.IsWindows()) return Unavailable(utcNow, "WTS console observations require Windows.");
        try
        {
            uint id = WTSGetActiveConsoleSessionId();
            if (id == uint.MaxValue) return new() { CapturedAtUtc = utcNow, Availability = SecurityObservationAvailability.Available };
            if (id > int.MaxValue) return Unavailable(utcNow, "Physical-console session ID is invalid.");
            int session = (int)id;
            ushort? protocol = ReadProtocol(session);
            if (protocol != 0) return Unavailable(utcNow, "Physical-console protocol is unavailable or identifies a remote session.");
            var info = ReadInfo(session);
            if (info == null || info.Value.SessionId != session || info.Value.SessionState != 0)
                return Unavailable(utcNow, "Physical-console extended metadata is unavailable or inactive.");
            // Windows 7/Server 2008 R2 invert these flags. They are outside this .NET runtime's supported OS range.
            if (Environment.OSVersion.Version < new Version(6, 2))
                return Unavailable(utcNow, "Legacy WTS lock-state semantics need a separate compatibility adapter.");
            bool? locked = info.Value.SessionFlags switch { 0 => true, 1 => false, _ => null };
            TimeSpan? idle = info.Value.CurrentTime > 0 && info.Value.LastInputTime > 0 &&
                info.Value.CurrentTime >= info.Value.LastInputTime
                ? TimeSpan.FromTicks(info.Value.CurrentTime - info.Value.LastInputTime) : null;
            if (WTSGetActiveConsoleSessionId() != id)
                return Unavailable(utcNow, "Physical-console session changed while its metadata was being queried.");
            return new()
            {
                CapturedAtUtc = utcNow, SessionId = session, ClientProtocolType = protocol, IsLocked = locked,
                IdleDuration = idle, Availability = SecurityObservationAvailability.Available,
                Limitation = locked == null || (locked == false && idle == null) ? "Console lock/idle metadata is incomplete." : null
            };
        }
        catch (Exception exception) when (exception is ExternalException or ArgumentException or DllNotFoundException or EntryPointNotFoundException)
        {
            logger?.LogWarning(exception, "Physical-console WTS observation failed; no presence was inferred.");
            return Unavailable(utcNow, "Physical-console query failed.");
        }
    }

    private static ConsolePresenceObservation Unavailable(DateTime now, string reason) => new()
    { CapturedAtUtc = now, Availability = SecurityObservationAvailability.Unavailable, Limitation = reason };

    private static ushort? ReadProtocol(int session)
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            return WTSQuerySessionInformationW(IntPtr.Zero, session, 16, out buffer, out int bytes) &&
                buffer != IntPtr.Zero && bytes >= sizeof(ushort) ? unchecked((ushort)Marshal.ReadInt16(buffer)) : null;
        }
        finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
    }

    private static WtsInfoExLevel1? ReadInfo(int session)
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!WTSQuerySessionInformationW(IntPtr.Zero, session, 25, out buffer, out int bytes) ||
                buffer == IntPtr.Zero || bytes < Marshal.SizeOf<WtsInfoEx>()) return null;
            var value = Marshal.PtrToStructure<WtsInfoEx>(buffer);
            return value.Level == 1 ? value.Data : null;
        }
        finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
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
    private struct WtsInfoEx { public uint Level; public WtsInfoExLevel1 Data; }
    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr buffer);
}
