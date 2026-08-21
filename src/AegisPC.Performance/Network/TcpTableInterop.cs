using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using AegisPC.Core.Models;

namespace AegisPC.Performance.Network
{
    public static class TcpTableInterop
    {
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public uint owningPid;

            public ushort LocalPort => (ushort)((localPort1 << 8) | localPort2);
            public ushort RemotePort => (ushort)((remotePort1 << 8) | remotePort2);
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            uint ulAf,
            TCP_TABLE_CLASS TableClass,
            uint Reserved = 0);

        public static List<NetworkConnection> GetAllTcpConnections()
        {
            var connections = new List<NetworkConnection>();
            int bufferSize = 0;

            // First call to determine buffer size
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
            if (bufferSize <= 0) return connections;

            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                uint result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
                if (result != 0) return connections;

                int numEntries = Marshal.ReadInt32(tcpTablePtr);
                IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    var localIp = new IPAddress(row.localAddr).ToString();
                    var remoteIp = new IPAddress(row.remoteAddr).ToString();

                    connections.Add(new NetworkConnection
                    {
                        PID = (int)row.owningPid,
                        Protocol = "TCP",
                        LocalAddress = localIp,
                        LocalPort = row.LocalPort,
                        RemoteAddress = remoteIp,
                        RemotePort = row.RemotePort,
                        State = MapTcpState(row.state)
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }

            return connections;
        }

        private static string MapTcpState(uint state) => state switch
        {
            1 => "CLOSED",
            2 => "LISTENING",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT_1",
            7 => "FIN_WAIT_2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "UNKNOWN"
        };
    }
}
