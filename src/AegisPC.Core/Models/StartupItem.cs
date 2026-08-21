using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class StartupItem
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string? Publisher { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string? Arguments { get; set; }
    public string Source { get; set; } = string.Empty;
    public string? RegistryPath { get; set; }
    public bool IsEnabled { get; set; }
    public ImpactLevel ImpactLevel { get; set; }
    public RiskLevel RiskLevel { get; set; }
    public string? BackupValue { get; set; }
    public DateTime LastAnalyzedAt { get; set; } = DateTime.UtcNow;
}
