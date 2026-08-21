using System;
using System.Collections.Generic;

namespace AegisPC.Core.Models
{
    public class ProtectedFolder
    {
        public string Path { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public bool IsSystemDefault { get; set; }
        public bool AddedByUser { get; set; }
        public bool IsEnabled { get; set; } = true;
        public bool IsProtected { get; set; } = true;
        public long SizeBytes { get; set; }
        public string Policy { get; set; } = "Strict"; // Strict, Adaptive, AuditOnly
        public List<string> CustomAllowedProcessPaths { get; set; } = new();
    }
}
