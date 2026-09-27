using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Infrastructure.Ipc;

/// <summary>Authenticates an IPC server against Windows SCM, not a caller-controlled pipe name or status payload.</summary>
public static class PipeServiceIdentity
{
    /// <summary>
    /// Returns true only if the connected pipe belongs to the running named service's SCM-reported process.
    /// Failure to query either identity fails closed; console/debug listeners are not installed services.
    /// </summary>
    public static bool IsExpectedService(NamedPipeClientStream pipe, string serviceName)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (string.IsNullOrWhiteSpace(serviceName) || !pipe.IsConnected ||
            !GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var serverProcessId)) return false;
        var manager = OpenSCManager(null, null, 0x0001); // SC_MANAGER_CONNECT only
        if (manager == IntPtr.Zero) return false;
        try
        {
            var service = OpenService(manager, serviceName, 0x0004); // SERVICE_QUERY_STATUS only
            if (service == IntPtr.Zero) return false;
            try
            {
                return QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatusProcess>(), out _) &&
                    status.CurrentState == 4 && status.ProcessId != 0 && status.ProcessId == serverProcessId;
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, out ServiceStatusProcess status,
        int bufferSize, out int bytesNeeded);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr service);
}
