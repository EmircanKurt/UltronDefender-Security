using AegisPC.Core.Models;

namespace AegisPC.Contracts.Events;

public class ScanProgressEvent
{
    public ScanProgress Progress { get; set; } = new();
}
