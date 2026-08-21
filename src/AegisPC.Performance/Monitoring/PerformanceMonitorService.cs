using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Performance.Monitoring
{
    /// <summary>
    /// Background telemetry service collecting CPU, Memory, Disk, Network and active processes metrics.
    /// </summary>
    public class PerformanceMonitorService : IPerformanceMonitor, IDisposable
    {
        private readonly CpuMonitor _cpuMonitor = new();
        private readonly MemoryMonitor _memoryMonitor = new();
        private readonly DiskMonitor _diskMonitor = new();
        private readonly ILogger<PerformanceMonitorService>? _logger;
        private readonly Func<PerformanceSample, CancellationToken, Task>? _samplePersister;

        private CancellationTokenSource? _cts;
        private Task? _monitorTask;
        private long _prevNetBytesReceived;
        private long _prevNetBytesSent;
        private DateTime _prevNetSampleTime = DateTime.UtcNow;

        public event EventHandler<PerformanceSample>? OnSampleCollected;
        public int SampleInterval { get; set; } = 2000;

        public PerformanceMonitorService(
            Func<PerformanceSample, CancellationToken, Task>? samplePersister = null,
            ILogger<PerformanceMonitorService>? logger = null)
        {
            _samplePersister = samplePersister;
            _logger = logger;
            InitNetworkCounters();
        }

        private void InitNetworkCounters()
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in interfaces)
                {
                    if (ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var stats = ni.GetIPv4Statistics();
                        _prevNetBytesReceived += stats.BytesReceived;
                        _prevNetBytesSent += stats.BytesSent;
                    }
                }
            }
            catch
            {
                // Network stats non-critical fallback
            }
        }

        public Task<PerformanceSample> GetCurrentSampleAsync()
        {
            var cpu = _cpuMonitor.GetCpuUsagePercentage();
            var (totalMem, usedMem, freeMem, memPercent) = _memoryMonitor.GetMemoryMetrics();
            var (totalDisk, freeDisk, usedDisk, diskPercent) = _diskMonitor.GetTotalDiskMetrics();

            // Calculate network throughput
            long currentBytesRecv = 0;
            long currentBytesSent = 0;
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in interfaces)
                {
                    if (ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var stats = ni.GetIPv4Statistics();
                        currentBytesRecv += stats.BytesReceived;
                        currentBytesSent += stats.BytesSent;
                    }
                }
            }
            catch { }

            var now = DateTime.UtcNow;
            var elapsedSeconds = Math.Max(0.1, (now - _prevNetSampleTime).TotalSeconds);
            long netDownBps = (long)Math.Max(0, (currentBytesRecv - _prevNetBytesReceived) / elapsedSeconds);
            long netUpBps = (long)Math.Max(0, (currentBytesSent - _prevNetBytesSent) / elapsedSeconds);

            _prevNetBytesReceived = currentBytesRecv;
            _prevNetBytesSent = currentBytesSent;
            _prevNetSampleTime = now;

            int procCount = 0;
            try
            {
                procCount = global::System.Diagnostics.Process.GetProcesses().Length;
            }
            catch { }

            var sample = new PerformanceSample
            {
                CpuPercent = cpu,
                MemoryUsedBytes = usedMem,
                MemoryTotalBytes = totalMem,
                DiskReadBps = 0,
                DiskWriteBps = 0,
                DiskUsagePercent = diskPercent,
                NetworkDownBps = netDownBps,
                NetworkUpBps = netUpBps,
                ActiveProcesses = procCount,
                SampledAt = now
            };

            return Task.FromResult(sample);
        }

        public Task StartMonitoringAsync()
        {
            if (_monitorTask != null && !_monitorTask.IsCompleted)
            {
                return Task.CompletedTask;
            }

            _cts = new CancellationTokenSource();
            _monitorTask = Task.Run(async () =>
            {
                _logger?.LogInformation("Performance monitoring loop started.");
                while (!_cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        var sample = await GetCurrentSampleAsync();
                        OnSampleCollected?.Invoke(this, sample);

                        if (_samplePersister != null)
                        {
                            await _samplePersister(sample, _cts.Token);
                        }

                        await Task.Delay(SampleInterval, _cts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning(ex, "Error occurred during performance telemetry collection.");
                        await Task.Delay(1000, _cts.Token);
                    }
                }
            }, _cts.Token);

            return Task.CompletedTask;
        }

        public async Task StopMonitoringAsync()
        {
            if (_cts != null)
            {
                _cts.Cancel();
                if (_monitorTask != null)
                {
                    try { await _monitorTask; } catch (OperationCanceledException) { }
                }
                _cts.Dispose();
                _cts = null;
                _monitorTask = null;
            }
        }

        public void Dispose()
        {
            _cts?.Cancel();
            _cts?.Dispose();
        }
    }
}
