using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models
{
    public class BlockedConnection
    {
        public string? Domain { get; set; }
        public string? IpAddress { get; set; }
        public int Port { get; set; }
        public ThreatCategory Category { get; set; }
        public string? ProcessName { get; set; }
        public int ProcessId { get; set; }
        public DateTime BlockedAt { get; set; }
    }
}
