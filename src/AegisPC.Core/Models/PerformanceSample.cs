using System;

namespace AegisPC.Core.Models;

public class PerformanceSample
{
    public double CpuPercent { get; set; }
    public long MemoryUsedBytes { get; set; }
    public long MemoryTotalBytes { get; set; }
    public long DiskReadBps { get; set; }
    public long DiskWriteBps { get; set; }
    public double DiskUsagePercent { get; set; }
    public long NetworkDownBps { get; set; }
    public long NetworkUpBps { get; set; }
    public int ActiveProcesses { get; set; }
    public DateTime SampledAt { get; set; } = DateTime.UtcNow;
}
