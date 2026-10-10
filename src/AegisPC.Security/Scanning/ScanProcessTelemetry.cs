using System;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>Samples the scanner process, not whole-machine utilization or managed heap alone.</summary>
public sealed class ScanProcessTelemetry : IDisposable
{
    private readonly Process _process = Process.GetCurrentProcess();
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly ILogger? _logger;
    private TimeSpan _previousCpu;
    private TimeSpan _previousWall;
    private double _cpuPercent;
    private double _workingSetMb;
    private double _peakObservedWorkingSetMb;
    private bool _hasCpuSample;
    /// <summary>True only after a working-set query succeeded; zero without this flag is not a measured peak.</summary>
    public bool HasWorkingSetSample { get; private set; }

    /// <summary>Largest working set observed by this scan's samples; not an OS-guaranteed instantaneous peak.</summary>
    public double PeakObservedWorkingSetMb => _peakObservedWorkingSetMb;

    /// <summary>Establishes a CPU baseline without blocking or artificially loading the machine.</summary>
    public ScanProcessTelemetry(ILogger? logger = null)
    {
        _logger = logger;
        try { _previousCpu = _process.TotalProcessorTime; }
        catch (Exception ex) { _logger?.LogWarning(ex, "Initial scanner CPU telemetry was unavailable."); }
        _previousWall = _clock.Elapsed;
    }

    /// <summary>Returns cached samples for frequent callbacks; CPU deltas need at least 250 ms.</summary>
    public (double CpuPercent, double WorkingSetMb, bool HasCpuSample) Sample()
    {
        try
        {
            _process.Refresh();
            _workingSetMb = _process.WorkingSet64 / 1048576.0;
            HasWorkingSetSample = true;
            _peakObservedWorkingSetMb = Math.Max(_peakObservedWorkingSetMb, _workingSetMb);
            var wall = _clock.Elapsed;
            if (wall - _previousWall >= TimeSpan.FromMilliseconds(250))
            {
                var cpu = _process.TotalProcessorTime;
                _cpuPercent = CalculateCpuPercent(cpu - _previousCpu, wall - _previousWall, Environment.ProcessorCount);
                _previousCpu = cpu;
                _previousWall = wall;
                _hasCpuSample = true;
            }
        }
        catch (Exception ex)
        {
            _hasCpuSample = false;
            _logger?.LogDebug(ex, "Scanner process telemetry could not be refreshed.");
        }
        return (_cpuPercent, _workingSetMb, _hasCpuSample);
    }

    /// <summary>Normalizes process CPU time over elapsed monotonic time and logical processors to 0–100 percent.</summary>
    public static double CalculateCpuPercent(TimeSpan cpuDelta, TimeSpan wallDelta, int logicalProcessors)
    {
        if (cpuDelta < TimeSpan.Zero || wallDelta <= TimeSpan.Zero || logicalProcessors <= 0) return 0;
        return Math.Clamp(cpuDelta.TotalSeconds / wallDelta.TotalSeconds / logicalProcessors * 100, 0, 100);
    }

    /// <summary>Releases the process query handle; never terminates the process.</summary>
    public void Dispose() => _process.Dispose();
}
