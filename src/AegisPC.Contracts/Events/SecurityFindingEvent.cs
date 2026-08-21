using System;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Events;

public class SecurityFindingEvent
{
    public SecurityFinding Finding { get; set; } = new();
    public string EventType { get; set; } = string.Empty;
}
