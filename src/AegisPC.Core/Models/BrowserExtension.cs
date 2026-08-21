using System.Collections.Generic;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class BrowserExtension
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<string> Permissions { get; set; } = new();
    public bool IsEnabled { get; set; }
    public bool IsSideloaded { get; set; }
    public string? UpdateUrl { get; set; }
    public string? ManifestPath { get; set; }
    public RiskLevel RiskLevel { get; set; }
    public List<string> RiskReasons { get; set; } = new();
}
