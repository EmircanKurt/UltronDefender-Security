using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

public class ProcessInfo
{
    public byte[]? Icon { get; set; }
    public string Name { get; set; } = string.Empty;
    public int PID { get; set; }
    public string? Publisher { get; set; }
    public double CpuPercent { get; set; }
    public long MemoryBytes { get; set; }
    public double GpuPercent { get; set; }
    public long DiskReadBps { get; set; }
    public long DiskWriteBps { get; set; }
    public long NetworkBps { get; set; }
    public DateTime StartTime { get; set; }
    public string ExecutablePath { get; set; } = string.Empty;
    public bool IsSigned { get; set; }
    public string? SignaturePublisher { get; set; }
    public string? UserName { get; set; }
    public RiskLevel RiskLevel { get; set; }
    public int ParentPid { get; set; }
    public int SessionId { get; set; }
}
