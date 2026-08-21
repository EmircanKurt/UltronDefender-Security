using System;

namespace AegisPC.Core.Models
{
    public class CloudReputation
    {
        public required string SHA256 { get; set; }
        public required string Verdict { get; set; }
        public int DetectionCount { get; set; }
        public required string Source { get; set; }
        public DateTime? FirstSeen { get; set; }
        public DateTime CheckedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
    }
}
