using System;

namespace AegisPC.Core.Models
{
    public class AllowedRansomwareApplication
    {
        public string ExecutablePath { get; set; } = string.Empty;
        public string ApplicationName { get; set; } = string.Empty;
        public string? Publisher { get; set; }
        public string? SHA256 { get; set; }
        public bool IsSigned { get; set; }
        public bool IsSystemWhitelisted { get; set; }
        public DateTime AddedAt { get; set; } = DateTime.UtcNow;
    }
}
