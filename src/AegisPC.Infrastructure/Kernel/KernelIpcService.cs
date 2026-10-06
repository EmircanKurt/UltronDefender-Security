using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Infrastructure.Kernel
{
    /// <summary>
    /// Retains legacy transport framing for compatibility tests. Native listener/action activation remains
    /// closed until authenticated identity-bound protocol, signing and isolated VM validation exist.
    /// </summary>
    public class KernelIpcService : IDisposable
    {
        public const string DefaultPortName = "\\AegisFilterPort";
        private SafeFileHandle? _portHandle;
        private bool _isConnected;
        private readonly object _lock = new();

        public bool IsConnected => _isConnected && _portHandle != null && !_portHandle.IsInvalid;

        #region Protocol Structs Matching AegisFilter.sys Ring-0
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ScanRequest
        {
            public uint ProcessId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
            public string FilePath;
            [MarshalAs(UnmanagedType.I1)]
            public bool IsWriteOperation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ScanResponse
        {
            [MarshalAs(UnmanagedType.I1)]
            public bool BlockAccess;
        }

        /// <summary>
        /// Windows Filter Manager FILTER_MESSAGE_HEADER yapısı (x64'te 16 bayt: 4b ReplyLength + 4b Padding + 8b MessageId).
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct FilterMessageHeader
        {
            public uint ReplyLength;
            public uint Reserved;
            public ulong MessageId;
        }

        /// <summary>
        /// Windows Filter Manager FILTER_REPLY_HEADER yapısı (x64'te 16 bayt: 4b Status + 4b Padding + 8b MessageId).
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct FilterReplyHeader
        {
            public int Status;      // NTSTATUS (0x00000000 = STATUS_SUCCESS)
            public int Reserved;    // x64 8-bayt hizalama padding
            public ulong MessageId; // Kernel FltSendMessage ile eşleşen kimlik
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ScanReplyPacket
        {
            public FilterReplyHeader Header;
            public ScanResponse Response;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct AegisControlCommand
        {
            public uint CommandCode;
            public uint ProcessId;
        }
        #endregion

        #region Win32 FltLib P/Invoke
        [DllImport("fltLib.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int FilterConnectCommunicationPort(
            string lpPortName,
            uint dwOptions,
            IntPtr lpContext,
            ushort wSizeOfContext,
            IntPtr lpSecurityAttributes,
            out SafeFileHandle hPort);

        [DllImport("fltLib.dll", SetLastError = true)]
        private static extern int FilterGetMessage(
            SafeFileHandle hPort,
            IntPtr lpMessageBuffer,
            uint dwMessageBufferSize,
            IntPtr lpOverlapped);

        [DllImport("fltLib.dll", SetLastError = true)]
        private static extern int FilterReplyMessage(
            SafeFileHandle hPort,
            IntPtr lpReplyBuffer,
            uint dwReplyBufferSize);

        [DllImport("fltLib.dll", SetLastError = true)]
        private static extern int FilterSendMessage(
            SafeFileHandle hPort,
            IntPtr lpInBuffer,
            uint dwInBufferSize,
            IntPtr lpOutBuffer,
            uint dwOutBufferSize,
            out uint lpBytesReturned);
        #endregion

        public bool ConnectToDriver(string portName = DefaultPortName)
        {
            lock (_lock)
            {
                if (IsConnected) return true;

                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    _isConnected = false;
                    return false;
                }

                try
                {
                    int hResult = FilterConnectCommunicationPort(portName, 0, IntPtr.Zero, 0, IntPtr.Zero, out _portHandle);
                    _isConnected = (hResult == 0 && _portHandle != null && !_portHandle.IsInvalid);
                    return _isConnected;
                }
                catch
                {
                    _isConnected = false;
                    return false;
                }
            }
        }

        /// <summary>Rejects unauthenticated payload PID registration; no native anti-tamper authority is granted.</summary>
        public bool RegisterProtectedProcess(uint pid) => false;

        /// <summary>
        /// Refuses to activate the unverified legacy listener. A path/PID/boolean ABI lacks file identity,
        /// peer authentication and applied receipts; an experimental switch is not an enforcement permit.
        /// </summary>
        public void StartListener(Func<ScanRequest, bool> evaluationCallback, int workerThreads = 4)
        {
            ArgumentNullException.ThrowIfNull(evaluationCallback);
            throw new NotSupportedException("Legacy native listener is disabled until identity-bound protocol and isolated VM gates are verified.");
        }

        public void Disconnect()
        {
            lock (_lock)
            {
                if (_portHandle != null && !_portHandle.IsInvalid)
                {
                    _portHandle.Dispose();
                    _portHandle = null;
                }
                _isConnected = false;
            }
        }

        public void Dispose()
        {
            Disconnect();
        }
    }
}
