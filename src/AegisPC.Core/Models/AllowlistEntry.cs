using System;

namespace AegisPC.Core.Models;

public class AllowlistEntry
{
    public int Id { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string SHA256 { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string AddedBy { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public DateTime AddedAt { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; } = true;
}
