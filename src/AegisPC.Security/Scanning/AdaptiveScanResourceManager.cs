using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Implements <see cref="IScanResourceManager"/> providing dynamic, zero-freeze resource governance.
    /// Manages worker slot concurrency, cooperative pacing delays, and runtime profile transitions.
    /// </summary>
    public class AdaptiveScanResourceManager : IScanResourceManager, IDisposable
    {
        private readonly ILogger<AdaptiveScanResourceManager>? _logger;
        private readonly object _lock = new();
        private readonly bool _isHdd;
        private readonly int _logicalCores;
        private readonly long _totalRamBytes;

        private ScanResourceMode _currentMode = ScanResourceMode.Auto;
        private ScanResourceProfile _activeProfile;
        private SemaphoreSlim _slotGate;
        private int _currentAllocatedSlots;
        private int _slotDeficit;
        private readonly Timer? _telemetryTimer;

        public ScanResourceMode CurrentMode
        {
            get { lock (_lock) return _currentMode; }
        }

        public ScanResourceProfile ActiveProfile
        {
            get { lock (_lock) return _activeProfile; }
        }

        public event Action<ScanResourceProfile>? ProfileChanged;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private class MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;

            public MEMORYSTATUSEX()
            {
                dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);

        public AdaptiveScanResourceManager(
            string? samplePath = null,
            ILogger<AdaptiveScanResourceManager>? logger = null)
        {
            _logger = logger;
            _logicalCores = Math.Max(1, Environment.ProcessorCount);
            _isHdd = !string.IsNullOrWhiteSpace(samplePath) && !DiskHardwareHelper.IsSolidStateDrive(samplePath);
            _totalRamBytes = QueryTotalPhysicalMemoryBytes();

            _activeProfile = ScanResourceProfile.Create(
                _currentMode,
                _isHdd,
                _logicalCores,
                _totalRamBytes);

            ScanQueueCoordinator.ActiveResourceSummary = _activeProfile.SummaryText;

            _currentAllocatedSlots = _activeProfile.Concurrency;
            _slotGate = new SemaphoreSlim(_currentAllocatedSlots, Math.Max(512, _logicalCores * 8));

            // Periodic 3-second evaluation loop for Auto mode adaptation
            _telemetryTimer = new Timer(_ =>
            {
                if (CurrentMode == ScanResourceMode.Auto)
                {
                    RefreshProfile();
                }
            }, null, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3));
        }

        private static long QueryTotalPhysicalMemoryBytes()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var mem = new MEMORYSTATUSEX();
                    if (GlobalMemoryStatusEx(mem))
                    {
                        return (long)mem.ullTotalPhys;
                    }
                }
            }
            catch { }
            return 8L * 1024 * 1024 * 1024; // 8GB fallback
        }

        // CPU basınç ölçümü için son örnekleme durumu
        private DateTime _lastCpuSampleTime = DateTime.UtcNow;
        private TimeSpan _lastCpuTime = TimeSpan.Zero;
        private double _lastCpuPercent = 10.0;

        private (double MemoryPressure, double CpuPressure) QueryCurrentPressure()
        {
            double memPressure = 50.0;
            double cpuPressure = _lastCpuPercent;
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var mem = new MEMORYSTATUSEX();
                    if (GlobalMemoryStatusEx(mem))
                    {
                        memPressure = mem.dwMemoryLoad;
                    }
                }

                // Gerçek CPU kullanım ölçümü: son örnekleme aralığındaki CPU zamanı değişimi
                var now = DateTime.UtcNow;
                var elapsed = now - _lastCpuSampleTime;
                if (elapsed.TotalMilliseconds > 500)
                {
                    try
                    {
                        using var proc = Process.GetCurrentProcess();
                        var currentCpuTime = proc.TotalProcessorTime;
                        var cpuDelta = currentCpuTime - _lastCpuTime;
                        cpuPressure = (cpuDelta.TotalMilliseconds / (elapsed.TotalMilliseconds * _logicalCores)) * 100.0;
                        cpuPressure = Math.Clamp(cpuPressure, 0, 100);
                        _lastCpuSampleTime = now;
                        _lastCpuTime = currentCpuTime;
                        _lastCpuPercent = cpuPressure;
                    }
                    catch { }
                }
            }
            catch { }
            return (memPressure, cpuPressure);
        }

        public void SetMode(ScanResourceMode mode)
        {
            lock (_lock)
            {
                if (_currentMode == mode) return;
                _currentMode = mode;
                RebuildProfileInternal();
            }
        }

        public void RefreshProfile()
        {
            lock (_lock)
            {
                RebuildProfileInternal();
            }
        }

        private void RebuildProfileInternal()
        {
            var (memPressure, cpuPressure) = QueryCurrentPressure();
            var newProfile = ScanResourceProfile.Create(
                _currentMode,
                _isHdd,
                _logicalCores,
                _totalRamBytes,
                cpuPressure,
                memPressure);

            int oldConcurrency = _activeProfile.Concurrency;
            int newConcurrency = newProfile.Concurrency;
            _activeProfile = newProfile;
            ScanQueueCoordinator.ActiveResourceSummary = newProfile.SummaryText;

            // Dynamically adjust semaphore capacity
            if (newConcurrency > oldConcurrency)
            {
                int diff = newConcurrency - oldConcurrency;
                int deficitPayoff = Math.Min(_slotDeficit, diff);
                _slotDeficit -= deficitPayoff;
                int toRelease = diff - deficitPayoff;
                if (toRelease > 0)
                {
                    _slotGate.Release(toRelease);
                }
                _currentAllocatedSlots = newConcurrency;
            }
            else if (newConcurrency < oldConcurrency)
            {
                int diff = oldConcurrency - newConcurrency;
                int drained = 0;
                for (int i = 0; i < diff; i++)
                {
                    if (_slotGate.Wait(0))
                    {
                        drained++;
                    }
                    else
                    {
                        break;
                    }
                }
                _slotDeficit += (diff - drained);
                _currentAllocatedSlots = newConcurrency;
            }

            _logger?.LogInformation("Scan resource profile updated: {Profile}", newProfile.SummaryText);

            try
            {
                ProfileChanged?.Invoke(newProfile);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error notifying ProfileChanged listeners.");
            }
        }

        public async Task EnterWorkerSlotAsync(CancellationToken cancellationToken)
        {
            await _slotGate.WaitAsync(cancellationToken);
        }

        public void ExitWorkerSlot()
        {
            lock (_lock)
            {
                if (_slotDeficit > 0)
                {
                    _slotDeficit--;
                    return;
                }
            }

            try
            {
                _slotGate.Release();
            }
            catch (ObjectDisposedException) { }
        }

        public async Task ApplyPacingAsync(int processedFileCounter, CancellationToken cancellationToken)
        {
            int delayMs;
            int yieldFreq;
            long maxRam;

            lock (_lock)
            {
                delayMs = _activeProfile.DelayBetweenFilesMs;
                yieldFreq = _activeProfile.YieldFrequency;
                maxRam = _activeProfile.MaxMemoryBudgetBytes;
            }

            if (delayMs > 0)
            {
                await Task.Delay(delayMs, cancellationToken);
            }

            if (yieldFreq > 0 && (processedFileCounter % yieldFreq) == 0)
            {
                await Task.Yield();
            }

            // GC baskısını azalt: Sadece aşırı bellek taşması varsa ve 2500 dosyada bir kontrol et
            if ((processedFileCounter % 2500) == 0 && GC.GetTotalMemory(false) > (maxRam * 1.25))
            {
                GC.Collect(1, GCCollectionMode.Optimized, false, false);
                await Task.Delay(5, cancellationToken);
            }
        }

        public void Dispose()
        {
            _telemetryTimer?.Dispose();
            _slotGate?.Dispose();
        }
    }
}
