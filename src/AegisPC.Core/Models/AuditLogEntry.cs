using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class AuditLogEntry
{
    public int Id { get; set; }
    public AuditAction Action { get; set; }
    public string TargetType { get; set; } = string.Empty;
    public string TargetName { get; set; } = string.Empty;
    public string? TargetPath { get; set; }
    public string? Details { get; set; }
    public AuditResult Result { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
