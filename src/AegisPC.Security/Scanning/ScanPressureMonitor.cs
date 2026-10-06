using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AegisPC.Security.Scanning;

/// <summary>Reads scanner CPU and target-volume latency without changing disk policy or generating artificial work.</summary>
internal sealed class ScanPressureMonitor : IDisposable
{
    private readonly Process _process = Process.GetCurrentProcess();
    private TimeSpan _lastCpu;
    private long _lastWall = Stopwatch.GetTimestamp();
    private nint _query, _counter;
    private string _root = string.Empty;
    internal double CpuPercent { get; private set; }
    internal double? LatencyMs { get; private set; }
    internal bool HasCpuSample { get; private set; }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct CounterValue
    {
        [FieldOffset(0)] public uint Status;
        [FieldOffset(8)] public double Value;
    }
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)] private static extern uint PdhOpenQueryW(string? source, nint user, out nint query);
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)] private static extern uint PdhAddEnglishCounterW(nint query, string path, nint user, out nint counter);
    [DllImport("pdh.dll")] private static extern uint PdhCollectQueryData(nint query);
    [DllImport("pdh.dll")] private static extern uint PdhGetFormattedCounterValue(nint counter, uint format, out uint type, out CounterValue value);
    [DllImport("pdh.dll")] private static extern uint PdhCloseQuery(nint query);

    internal ScanPressureMonitor() => _lastCpu = _process.TotalProcessorTime;

    internal void ConfigureTarget(string path)
    {
        string root = Path.GetPathRoot(Path.GetFullPath(path))?.TrimEnd('\\') ?? string.Empty;
        if (_root == root) return;
        CloseQuery();
        _root = root;
        if (!OperatingSystem.IsWindows() || root.Length != 2 || root[1] != ':') return;
        if (PdhOpenQueryW(null, 0, out _query) != 0) { _query = 0; return; }
        if (PdhAddEnglishCounterW(_query, $"\\LogicalDisk({root})\\Avg. Disk sec/Transfer", 0, out _counter) != 0)
            CloseQuery();
        else PdhCollectQueryData(_query);
    }

    internal void Sample()
    {
        long now = Stopwatch.GetTimestamp();
        TimeSpan wall = Stopwatch.GetElapsedTime(_lastWall, now);
        if (wall.TotalMilliseconds >= 500)
        {
            TimeSpan cpu = _process.TotalProcessorTime;
            CpuPercent = ScanProcessTelemetry.CalculateCpuPercent(cpu - _lastCpu, wall, Environment.ProcessorCount);
            HasCpuSample = true;
            _lastCpu = cpu;
            _lastWall = now;
        }
        LatencyMs = null;
        if (_query != 0 && _counter != 0 && PdhCollectQueryData(_query) == 0 &&
            PdhGetFormattedCounterValue(_counter, 0x200, out _, out var value) == 0 && value.Status <= 1 &&
            double.IsFinite(value.Value) && value.Value >= 0)
            LatencyMs = value.Value * 1000;
    }

    private void CloseQuery()
    {
        if (_query != 0) PdhCloseQuery(_query);
        _query = _counter = 0;
        LatencyMs = null;
    }

    public void Dispose() { CloseQuery(); _process.Dispose(); }
}
