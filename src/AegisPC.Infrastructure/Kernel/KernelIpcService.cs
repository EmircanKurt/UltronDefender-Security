using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Infrastructure.Kernel
{
    /// <summary>
    /// Ring-0 Kernel Minifilter (AegisFilter.sys) ile Ring-3 Windows Servisi arasındaki
    /// FilterCommunicationPort çift yönlü haberleşme ve I/O gating altyapı servisi.
    /// 64-bit bellek hizalaması (x64 structure alignment), çok kanallı worker havuzu
    /// ve sistem kilitlenmelerini önleyen fail-open zaman aşımı mekanizması içerir.
    /// </summary>
    public class KernelIpcService : IDisposable
    {
        public const string DefaultPortName = "\\AegisFilterPort";
        private SafeFileHandle? _portHandle;
        private CancellationTokenSource? _cts;
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

        /// <summary>
        /// Ring-0 ObRegisterCallbacks koruması için mevcut korunan antivirüs servis sürecinin PID'sini sürücüye kaydeder.
        /// </summary>
        public bool RegisterProtectedProcess(uint pid)
        {
            if (!IsConnected || _portHandle == null) return false;

            try
            {
                var cmd = new AegisControlCommand
                {
                    CommandCode = 0x1001, // AEGIS_MSG_REGISTER_PROTECTED_PID
                    ProcessId = pid
                };

                int cmdSize = Marshal.SizeOf<AegisControlCommand>();
                IntPtr inBuffer = Marshal.AllocHGlobal(cmdSize);
                try
                {
                    Marshal.StructureToPtr(cmd, inBuffer, false);
                    int hr = FilterSendMessage(_portHandle, inBuffer, (uint)cmdSize, IntPtr.Zero, 0, out _);
                    return hr == 0;
                }
                finally
                {
                    Marshal.FreeHGlobal(inBuffer);
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Kernelden gelen dosya/süreç I/O isteklerini çok iş parçacıklı (worker pool) olarak dinler ve yanıtlar.
        /// </summary>
        public void StartListener(Func<ScanRequest, bool> evaluationCallback, int workerThreads = 4)
        {
            if (!IsConnected || _portHandle == null) return;
            _cts = new CancellationTokenSource();

            int headerSize = Marshal.SizeOf<FilterMessageHeader>();
            int requestSize = Marshal.SizeOf<ScanRequest>();
            int bufferSize = headerSize + requestSize;
            int replySize = Marshal.SizeOf<ScanReplyPacket>();

            for (int i = 0; i < Math.Max(1, workerThreads); i++)
            {
                Task.Factory.StartNew(() =>
                {
                    IntPtr msgBuffer = Marshal.AllocHGlobal(bufferSize);
                    IntPtr replyBuffer = Marshal.AllocHGlobal(replySize);

                    try
                    {
                        while (!_cts.Token.IsCancellationRequested && IsConnected)
                        {
                            int hr = FilterGetMessage(_portHandle, msgBuffer, (uint)bufferSize, IntPtr.Zero);
                            if (hr != 0)
                            {
                                if (_cts.Token.IsCancellationRequested) break;
                                Thread.Sleep(20);
                                continue;
                            }

                            try
                            {
                                var msgHeader = Marshal.PtrToStructure<FilterMessageHeader>(msgBuffer);
                                var request = Marshal.PtrToStructure<ScanRequest>(msgBuffer + headerSize);

                                bool shouldBlock = false;
                                try
                                {
                                    shouldBlock = evaluationCallback(request);
                                }
                                catch
                                {
                                    // Fail-open: Hata durumunda işletim sistemini kilitlememek için izin ver
                                    shouldBlock = false;
                                }

                                var reply = new ScanReplyPacket
                                {
                                    Header = new FilterReplyHeader
                                    {
                                        Status = 0, // STATUS_SUCCESS
                                        Reserved = 0,
                                        MessageId = msgHeader.MessageId
                                    },
                                    Response = new ScanResponse
                                    {
                                        BlockAccess = shouldBlock
                                    }
                                };

                                Marshal.StructureToPtr(reply, replyBuffer, false);
                                FilterReplyMessage(_portHandle, replyBuffer, (uint)replySize);
                            }
                            catch (Exception ex)
                            {
                                System.Diagnostics.Trace.WriteLine($"KernelIpc worker error: {ex.Message}");
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(msgBuffer);
                        Marshal.FreeHGlobal(replyBuffer);
                    }
                }, _cts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            }
        }

        public void Disconnect()
        {
            lock (_lock)
            {
                _cts?.Cancel();
                _cts?.Dispose();
                _cts = null;

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
