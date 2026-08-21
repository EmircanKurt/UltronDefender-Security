using System;

namespace AegisPC.Contracts.Events;

public class PerformanceAlertEvent
{
    public string AlertType { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public double CurrentValue { get; set; }
    public double ThresholdValue { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
