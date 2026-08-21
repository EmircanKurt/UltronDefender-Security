using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class CrashEvent
{
    public CrashEventType EventType { get; set; }
    public string ApplicationName { get; set; } = string.Empty;
    public string ApplicationPath { get; set; } = string.Empty;
    public string? ExceptionCode { get; set; }
    public int EventId { get; set; }
    public string ProviderName { get; set; } = string.Empty;
    public DateTime OccurredAt { get; set; }
    public double? CpuAtTime { get; set; }
    public long? MemoryAtTime { get; set; }
    public Guid CorrelationId { get; set; } = Guid.NewGuid();
    public string? RawEventData { get; set; }
    public string? AnalysisResult { get; set; }
    public ConfidenceLevel ConfidenceLevel { get; set; }
}
