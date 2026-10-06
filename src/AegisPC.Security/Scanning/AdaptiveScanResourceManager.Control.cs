using System.Diagnostics;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>Controls useful admission from observed CPU, latency and completion throughput; never fills resource targets artificially.</summary>
public partial class AdaptiveScanResourceManager
{
    private readonly ScanPressureMonitor _scanPressure = new();
    private int _completedFiles;
    private int _lastCompletedFiles;
    private long _throughputSampleAt = Stopwatch.GetTimestamp();
    private double _previousThroughput;
    private bool _trialIncrease;
    private int _measuredStableIncreaseSamples;
    private bool _initialMeasuredPolicyReady;

    /// <summary>Reports monotonically completed file work, including cache hits, for admission experiments; not a malware statistic.</summary>
    public void ReportCompletedFiles(int completedFiles) => Interlocked.Add(ref _completedFiles, Math.Max(0, completedFiles));

    private ScanResourceProfile ApplyMeasuredControl(ScanResourceProfile requested, double systemCpu, bool allowIncrease)
    {
        try { if (_workloadSampler == null) _scanPressure.Sample(); }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Scanner pressure telemetry unavailable; automatic expansion is deferred.");
            return ScanResourceProfile.Create(requested.Mode, requested.IsHddRestricted, _logicalCores,
                _totalRamBytes, double.NaN, double.NaN);
        }
        var sample = _workloadSampler?.Invoke() ??
            (_scanPressure.HasCpuSample ? (double?)_scanPressure.CpuPercent : null, _mixedVolumes ? null : _scanPressure.LatencyMs);
        double? scannerCpu = sample.Item1 is double cpu && double.IsFinite(cpu) ? Math.Clamp(cpu, 0, 100) : null;
        double? diskLatency = sample.Item2 is double ms && double.IsFinite(ms) && ms >= 0 ? ms : null;
        double target = double.IsFinite(systemCpu) && scannerCpu.HasValue ? Math.Clamp(70 - Math.Max(0, systemCpu - scannerCpu.Value), 5, 40) : 40;
        int current = _activeProfile.Concurrency;
        int workers = Math.Min(current, requested.MaximumConcurrency);
        string reason = requested.LimitingReason;
        bool busy = scannerCpu.HasValue && (scannerCpu.Value > target + 5 || systemCpu >= 70);
        bool slowDisk = diskLatency is double latency && latency > (requested.IsHddRestricted ? 25 : 10);
        // Initial missing telemetry must not permanently freeze the safe starting policy at its fallback.
        if (!_initialMeasuredPolicyReady && requested.Mode == ScanResourceMode.Auto && scannerCpu.HasValue &&
            double.IsFinite(systemCpu) && requested.LimitingReason.Length == 0 && !busy && !slowDisk)
        {
            workers = Math.Max(workers, requested.Concurrency);
            _initialMeasuredPolicyReady = true;
        }
        if (busy || slowDisk)
        {
            workers = Math.Max(1, workers / 2);
            reason = slowDisk ? "Disk gecikmesi" : "Diğer uygulamalar / CPU hedefi";
            _measuredStableIncreaseSamples = 0;
            _trialIncrease = false;
        }
        else if (requested.Mode != ScanResourceMode.Auto) workers = requested.Concurrency;
        else if (allowIncrease)
        {
            long now = Stopwatch.GetTimestamp();
            double elapsed = Stopwatch.GetElapsedTime(_throughputSampleAt, now).TotalSeconds;
            if (elapsed >= 2.5)
            {
                int completed = Volatile.Read(ref _completedFiles);
                double throughput = (completed - _lastCompletedFiles) / elapsed;
                bool improved = _previousThroughput <= 0 || throughput >= _previousThroughput * 1.10;
                if (_trialIncrease && !improved)
                {
                    workers = Math.Max(1, workers - 1);
                    reason = "Ek işçi verim kazandırmadı";
                    _measuredStableIncreaseSamples = -3;
                }
                else if (throughput > 0 && scannerCpu.HasValue && scannerCpu.Value < target - 5 &&
                         diskLatency.HasValue && ++_measuredStableIncreaseSamples >= 3)
                {
                    workers = Math.Min(requested.MaximumConcurrency, workers + 1);
                    _measuredStableIncreaseSamples = 0;
                }
                _trialIncrease = workers > current;
                _previousThroughput = throughput;
                _lastCompletedFiles = completed;
                _throughputSampleAt = now;
            }
        }
        workers = Math.Clamp(workers, 1, Math.Max(1, requested.MaximumConcurrency));
        string summary = $"Sistem Gereksinimleri • {requested.Mode} • {workers} işçi • RAM bütçesi {requested.MaxMemoryBudgetBytes / 1048576:N0} MiB • CPU hedefi ~%{target:0}";
        if (requested.IsHddRestricted) summary += " • HDD/Belirsiz disk";
        if (!diskLatency.HasValue) summary += " • Disk ölçümü alınamadı";
        if (reason.Length > 0) summary += " • " + reason;
        return new ScanResourceProfile
        {
            Mode = requested.Mode, Concurrency = workers, MaximumConcurrency = requested.MaximumConcurrency,
            ChannelCapacity = requested.ChannelCapacity, BatchSize = requested.BatchSize,
            DelayBetweenFilesMs = requested.DelayBetweenFilesMs, YieldFrequency = requested.YieldFrequency,
            MaxMemoryBudgetBytes = requested.MaxMemoryBudgetBytes, IsHddRestricted = requested.IsHddRestricted,
            CpuTargetPercent = target, LimitingReason = reason, SummaryText = summary,
            IsAdmissionPaused = requested.IsAdmissionPaused
        };
    }
}
