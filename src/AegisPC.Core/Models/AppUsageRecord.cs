using System;

namespace AegisPC.Core.Models
{
    public class AppUsageRecord
    {
        public required string AppName { get; set; }
        public string? AppPath { get; set; }
        public string? Category { get; set; }
        public long UsageSeconds { get; set; }
        public DateTime Date { get; set; }
    }
}
