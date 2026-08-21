using System;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IPerformanceMonitor
{
    Task<PerformanceSample> GetCurrentSampleAsync();
    Task StartMonitoringAsync();
    Task StopMonitoringAsync();
    event EventHandler<PerformanceSample>? OnSampleCollected;
    int SampleInterval { get; set; }
}
