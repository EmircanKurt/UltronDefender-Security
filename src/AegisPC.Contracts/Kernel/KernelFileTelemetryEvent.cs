using System;

namespace AegisPC.Contracts.Kernel
{
    public enum MinifilterOperationType
    {
        PreCreate = 1,
        PostCreate = 2,
        PreWrite = 3,
        PostWrite = 4,
        PreCleanup = 5,
        PreSetInformation = 6,
        PreRename = 7
    }

    public enum KernelGatingStatus
    {
        Allowed = 0,
        BlockedAccessDenied = 1,
        BlockedSharingViolation = 2,
        TimeoutFallbackAllowed = 3,
        BypassedTrustedProcess = 4
    }

    public class KernelFileTelemetryEvent
    {
        public ulong EventSequenceNumber { get; set; }
        public string CorrelationId { get; set; } = Guid.NewGuid().ToString("N");
        public MinifilterOperationType OperationType { get; set; }
        public int ProcessId { get; set; }
        public int ThreadId { get; set; }
        public string ProcessImageName { get; set; } = string.Empty;
        public string NtDevicePath { get; set; } = string.Empty;
        public string CanonicalDosPath { get; set; } = string.Empty;
        public uint DesiredAccess { get; set; }
        public uint ShareAccess { get; set; }
        public uint CreateDisposition { get; set; }
        public uint FileAttributes { get; set; }
        public bool IsPagingIo { get; set; }
        public bool IsDirectory { get; set; }
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    }
}
