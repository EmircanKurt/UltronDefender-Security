using System;
using System.Runtime.InteropServices;
using AegisPC.Infrastructure.Kernel;
using Xunit;

namespace AegisPC.Tests
{
    public class KernelIpcFramingTests
    {
        [Fact]
        public void FilterMessageHeader_MatchesWindowsFilterManager_X64Layout()
        {
            // Windows x64 Filter Manager FILTER_MESSAGE_HEADER:
            // ULONG ReplyLength (4 bytes)
            // ULONG Reserved/Padding (4 bytes)
            // ULONG64 MessageId (8 bytes, 8-byte aligned)
            // Total size: 16 bytes.
            int size = Marshal.SizeOf<KernelIpcService.FilterMessageHeader>();
            Assert.Equal(16, size);

            int messageIdOffset = (int)Marshal.OffsetOf<KernelIpcService.FilterMessageHeader>("MessageId");
            Assert.Equal(8, messageIdOffset);
        }

        [Fact]
        public void FilterReplyHeader_MatchesWindowsFilterManager_X64Layout()
        {
            // Windows x64 Filter Manager FILTER_REPLY_HEADER:
            // NTSTATUS Status (4 bytes)
            // ULONG Reserved/Padding (4 bytes)
            // ULONG64 MessageId (8 bytes, 8-byte aligned)
            // Total size: 16 bytes.
            int size = Marshal.SizeOf<KernelIpcService.FilterReplyHeader>();
            Assert.Equal(16, size);

            int messageIdOffset = (int)Marshal.OffsetOf<KernelIpcService.FilterReplyHeader>("MessageId");
            Assert.Equal(8, messageIdOffset);
        }

        [Fact]
        public void AegisControlCommand_MatchesKernelStructLayout()
        {
            // CommandCode (4 bytes) + ProcessId (4 bytes) = 8 bytes
            int size = Marshal.SizeOf<KernelIpcService.AegisControlCommand>();
            Assert.Equal(8, size);

            var cmd = new KernelIpcService.AegisControlCommand
            {
                CommandCode = 0x1001,
                ProcessId = 1234
            };

            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(cmd, ptr, false);
                int code = Marshal.ReadInt32(ptr, 0);
                int pid = Marshal.ReadInt32(ptr, 4);

                Assert.Equal(0x1001, code);
                Assert.Equal(1234, pid);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        [Fact]
        public void ScanReplyPacket_EnvelopesHeaderAndResponseAccurately()
        {
            int expectedHeaderSize = 16;
            int responseSize = Marshal.SizeOf<KernelIpcService.ScanResponse>();
            int packetSize = Marshal.SizeOf<KernelIpcService.ScanReplyPacket>();

            Assert.Equal(expectedHeaderSize + responseSize, packetSize);

            var packet = new KernelIpcService.ScanReplyPacket
            {
                Header = new KernelIpcService.FilterReplyHeader
                {
                    Status = 0,
                    Reserved = 0,
                    MessageId = 998877665544ul
                },
                Response = new KernelIpcService.ScanResponse
                {
                    BlockAccess = true
                }
            };

            IntPtr ptr = Marshal.AllocHGlobal(packetSize);
            try
            {
                Marshal.StructureToPtr(packet, ptr, false);
                var deserialized = Marshal.PtrToStructure<KernelIpcService.ScanReplyPacket>(ptr);

                Assert.Equal(0, deserialized.Header.Status);
                Assert.Equal(998877665544ul, deserialized.Header.MessageId);
                Assert.True(deserialized.Response.BlockAccess);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }
}
