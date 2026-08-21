using AegisPC.Core.Models;

namespace AegisPC.Contracts.Events;

public class ProcessChangedEvent
{
    public string ChangeType { get; set; } = string.Empty;
    public ProcessInfo ProcessInfo { get; set; } = new();
}
