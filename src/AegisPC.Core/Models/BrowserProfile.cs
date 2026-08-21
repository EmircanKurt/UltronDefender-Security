using System.Collections.Generic;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class BrowserProfile
{
    public BrowserType BrowserType { get; set; }
    public string ProfileName { get; set; } = string.Empty;
    public string ProfilePath { get; set; } = string.Empty;
    public List<BrowserExtension> Extensions { get; set; } = new();
}
