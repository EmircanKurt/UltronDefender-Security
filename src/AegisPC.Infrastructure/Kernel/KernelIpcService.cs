using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Infrastructure.Kernel
{
    public class KernelIpcService : IDisposable
    {
        private const string PortName = "\\AegisFilterPort";
        private SafeFileHandle? _portHandle;
        private CancellationTokenSource? _cts;

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

        [DllImport("fltLib.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int FilterConnectCommunicationPort(
            string lpPortName, uint dwOptions, IntPtr lpContext, ushort wSizeOfContext, IntPtr lpSecurityAttributes, out SafeFileHandle hPort);

        [DllImport("fltLib.dll", SetLastError = true)]
        private static extern int FilterGetMessage(
            SafeFileHandle hPort, IntPtr lpMessageBuffer, uint dwMessageBufferSize, IntPtr lpOverlapped);

        [DllImport("fltLib.dll", SetLastError = true)]
        private static extern int FilterReplyMessage(
            SafeFileHandle hPort, IntPtr lpReplyBuffer, uint dwReplyBufferSize);

        public bool ConnectToDriver()
        {
            try
            {
                int hResult = FilterConnectCommunicationPort(PortName, 0, IntPtr.Zero, 0, IntPtr.Zero, out _portHandle);
                return hResult == 0 && _portHandle != null && !_portHandle.IsInvalid;
            }
            catch
            {
                return false;
            }
        }

        public void StartListener(Func<ScanRequest, bool> evaluationCallback)
        {
            if (_portHandle == null || _portHandle.IsInvalid) return;
            _cts = new CancellationTokenSource();

            Task.Run(() =>
            {
                // Worker loop: Kernel'den I/O mesajlarını alıp karar döndürür
            }, _cts.Token);
        }

        public void Dispose()
        {
            _cts?.Cancel();
            _portHandle?.Dispose();
        }
    }
}
