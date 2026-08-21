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
                // Buffer size for kernel messages (header + ScanRequest)
                const int headerSize = 16; // FILTER_MESSAGE_HEADER size
                uint bufferSize = (uint)(headerSize + Marshal.SizeOf<ScanRequest>());
                IntPtr msgBuffer = Marshal.AllocHGlobal((int)bufferSize);

                try
                {
                    while (!_cts.Token.IsCancellationRequested)
                    {
                        int hr = FilterGetMessage(_portHandle, msgBuffer, bufferSize, IntPtr.Zero);
                        if (hr != 0)
                        {
                            if (_cts.Token.IsCancellationRequested) break;
                            Thread.Sleep(50); // Brief pause on error before retry
                            continue;
                        }

                        try
                        {
                            // Extract message ID from header (first 8 bytes = length, next 8 = message ID)
                            long messageId = Marshal.ReadInt64(msgBuffer, 8);

                            // Parse ScanRequest from buffer after header
                            var request = Marshal.PtrToStructure<ScanRequest>(msgBuffer + headerSize);

                            // Evaluate via callback (true = block, false = allow)
                            bool shouldBlock = evaluationCallback(request);

                            // Build reply: FILTER_REPLY_HEADER (messageId) + ScanResponse
                            int replyHeaderSize = 12; // Status(4) + MessageId(8)
                            int replySize = replyHeaderSize + Marshal.SizeOf<ScanResponse>();
                            IntPtr replyBuffer = Marshal.AllocHGlobal(replySize);

                            try
                            {
                                Marshal.WriteInt32(replyBuffer, 0); // STATUS_SUCCESS
                                Marshal.WriteInt64(replyBuffer, 4, messageId);
                                var response = new ScanResponse { BlockAccess = shouldBlock };
                                Marshal.StructureToPtr(response, replyBuffer + replyHeaderSize, false);

                                FilterReplyMessage(_portHandle, replyBuffer, (uint)replySize);
                            }
                            finally
                            {
                                Marshal.FreeHGlobal(replyBuffer);
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Trace.WriteLine($"KernelIpc message processing error: {ex.Message}");
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(msgBuffer);
                }
            }, _cts.Token);
        }

        public void Dispose()
        {
            _cts?.Cancel();
            _portHandle?.Dispose();
        }
    }
}
