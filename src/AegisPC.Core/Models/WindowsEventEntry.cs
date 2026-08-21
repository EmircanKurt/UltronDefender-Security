using System;

namespace AegisPC.Core.Models;

public class WindowsEventEntry
{
    public string LogName { get; set; } = string.Empty;
    public string ProviderName { get; set; } = string.Empty;
    public int EventId { get; set; }
    public string Level { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public DateTime TimeCreated { get; set; }
    public string MachineName { get; set; } = string.Empty;
    public int? ProcessId { get; set; }
    public string? RawXml { get; set; }
}
