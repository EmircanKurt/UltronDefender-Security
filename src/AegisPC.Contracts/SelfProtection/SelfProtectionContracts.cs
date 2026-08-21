using System;

namespace AegisPC.Contracts.SelfProtection
{
    public enum TamperTargetType
    {
        ServiceStop = 1,
        ProcessKill = 2,
        RegistryTamper = 3,
        FileDelete = 4,
        DriverUnload = 5
    }

    public class TamperAttemptEvent
    {
        public string EventId { get; set; } = Guid.NewGuid().ToString("N");
        public TamperTargetType TargetType { get; set; }
        public int SourcePid { get; set; }
        public string SourceProcessName { get; set; } = string.Empty;
        public string TargetResource { get; set; } = string.Empty;
        public bool WasBlocked { get; set; } = true;
        public string Details { get; set; } = string.Empty;
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    }

    public class SelfProtectionStatus
    {
        public bool IsServiceAclHardened { get; set; }
        public bool IsProcessProtectionActive { get; set; }
        public bool IsRegistryLockActive { get; set; }
        public bool IsVaultFileProtected { get; set; }
        public int BlockedTamperAttemptsCount { get; set; }
    }

    public interface ISelfProtectionEngine
    {
        event Action<TamperAttemptEvent>? OnTamperAttemptBlocked;
        SelfProtectionStatus GetStatus();
        bool ApplyProcessAclHardening();
        bool ProtectRegistryConfiguration();
        bool RecordAndBlockTamperAttempt(TamperTargetType type, int sourcePid, string sourceName, string targetResource, string details);
    }
}
