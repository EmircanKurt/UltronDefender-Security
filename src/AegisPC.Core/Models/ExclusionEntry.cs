using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models
{
    public class ExclusionEntry
    {
        public int Id { get; set; }
        public ExclusionType Type { get; set; } = ExclusionType.Path;
        public string Value { get; set; } = string.Empty;
        public DateTime AddedUtc { get; set; } = DateTime.UtcNow;
        public string? Reason { get; set; }
        public bool IncludeSubdirectories { get; set; } = true;
    }
}
