using System;

namespace AegisPC.Contracts.Kernel
{
    public class KernelIpcMessage
    {
        public ulong MessageId { get; set; }
        public uint ProtocolVersion { get; set; } = 1;
        public MinifilterOperationType OpCode { get; set; }
        public int ProcessId { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public uint DesiredAccess { get; set; }
        public uint TimeoutMs { get; set; } = 500; // 500ms max gating timeout
    }

    public class KernelReplyMessage
    {
        public ulong MessageId { get; set; }
        public uint NtStatus { get; set; } // 0 = STATUS_SUCCESS, 0xC0000022 = STATUS_ACCESS_DENIED
        public KernelGatingStatus GatingStatus { get; set; }
        public string Reason { get; set; } = string.Empty;
        public int RiskScore { get; set; }
        public double DecisionTimeMs { get; set; }
    }

    public class KernelGatingDecision
    {
        public bool IsBlocked { get; set; }
        public uint NtStatus { get; set; }
        public KernelGatingStatus Status { get; set; }
        public string BlockReason { get; set; } = string.Empty;
        public int RiskScore { get; set; }
        public double ElapsedMs { get; set; }
    }
}
