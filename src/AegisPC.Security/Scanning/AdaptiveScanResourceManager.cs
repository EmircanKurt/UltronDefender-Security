using System;
using System.Diagnostics;
using System.IO;
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
    /// Implements <see cref="IScanResourceManager"/> providing dynamic, cooperative resource governance.
    /// Manages worker slot concurrency, cooperative pacing delays, and runtime profile transitions.
    /// </summary>
    public partial class AdaptiveScanResourceManager : IScanResourceManager, IDisposable
    {
        private readonly ILogger<AdaptiveScanResourceManager>? _logger;
        private readonly object _lock = new();
        private bool _isHdd;
        private bool _mixedVolumes;
        private bool _disposed;
        private ScanResourceProfile? _pendingIncrease;
        private int _stableIncreaseSamples;
        private readonly int _logicalCores;
        private readonly long _totalRamBytes;
        private readonly Func<(double MemoryPressure, double CpuPressure, bool IsOnBattery)>? _pressureSampler;
        private readonly Func<(double? ScannerCpu, double? DiskLatencyMs)>? _workloadSampler;
        private readonly Func<string, bool> _storageClassifier;
        private readonly CancellationTokenSource _shutdownCancellation = new();
        private int _waitingWorkers;
        private bool _slotGateDisposed;

        private ScanResourceMode _currentMode = ScanResourceMode.Auto;
        private ScanResourceProfile _activeProfile;
        private SemaphoreSlim _slotGate;
        private int _currentAllocatedSlots;
        private int _slotDeficit;
        private readonly Timer? _telemetryTimer;

        /// <summary>Gets the requested policy independently of transient effective limits.</summary>
        public ScanResourceMode CurrentMode
        {
            get { lock (_lock) return _currentMode; }
        }

        /// <summary>Gets the current measured-hardware and pressure-limited scan budget.</summary>
        public ScanResourceProfile ActiveProfile
        {
            get { lock (_lock) return _activeProfile; }
        }

        /// <summary>Notifies consumers only when calculated limits or the requested mode change.</summary>
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

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeFileTime
        {
            public uint Low;
            public uint High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SystemPowerStatus
        {
            public byte ACLineStatus;
            public byte BatteryFlag;
            public byte BatteryLifePercent;
            public byte SystemStatusFlag;
            public uint BatteryLifeTime;
            public uint BatteryFullLifeTime;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSystemTimes(out NativeFileTime idleTime, out NativeFileTime kernelTime, out NativeFileTime userTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSystemPowerStatus(out SystemPowerStatus status);

        /// <summary>
        /// Samples physical RAM and target-volume storage once, then observes system pressure without a synthetic benchmark.
        /// An optional pressure sampler and disabled timer support deterministic policy tests, not hardware certification.
        /// </summary>
        public AdaptiveScanResourceManager(
            string? samplePath = null,
            ILogger<AdaptiveScanResourceManager>? logger = null,
            Func<(double MemoryPressure, double CpuPressure, bool IsOnBattery)>? pressureSampler = null,
            bool enableTelemetryTimer = true,
            Func<string, bool>? storageClassifier = null,
            Func<(double? ScannerCpu, double? DiskLatencyMs)>? workloadSampler = null)
        {
            _logger = logger;
            _pressureSampler = pressureSampler;
            _workloadSampler = workloadSampler;
            _storageClassifier = storageClassifier ?? DiskHardwareHelper.IsSolidStateDrive;
            _logicalCores = Math.Max(1, Environment.ProcessorCount);
            _isHdd = !_storageClassifier(ResolveStorageTarget(samplePath));
            _scanPressure.ConfigureTarget(ResolveStorageTarget(samplePath));
            _totalRamBytes = QueryTotalPhysicalMemoryBytes();
            var initialPressure = QueryCurrentPressure();

            _activeProfile = ScanResourceProfile.Create(
                _currentMode,
                _isHdd,
                _logicalCores,
                _totalRamBytes,
                initialPressure.CpuPressure,
                initialPressure.MemoryPressure,
                initialPressure.IsOnBattery);

            ScanQueueCoordinator.ActiveResourceSummary = _activeProfile.SummaryText;

            _currentAllocatedSlots = _activeProfile.Concurrency;
            _slotGate = new SemaphoreSlim(_currentAllocatedSlots, Math.Max(512, _logicalCores * 8));

            // Periodic 3-second evaluation loop for Auto mode adaptation
            // Manual modes also obey emergency memory limits after a scan has already started.
            if (enableTelemetryTimer)
                _telemetryTimer = new Timer(_ => RefreshProfile(), null, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3));
        }

        private long QueryTotalPhysicalMemoryBytes()
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
            catch (Exception ex) { _logger?.LogWarning(ex, "Physical memory capacity query failed; conservative runtime capacity is used."); }
            long runtimeCapacity = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
            return runtimeCapacity > 0 ? runtimeCapacity : 512L * 1024 * 1024;
        }

        // CPU basınç ölçümü için son örnekleme durumu
        private long _lastCpuSampleTimestamp = Stopwatch.GetTimestamp();
        private ulong _lastKernelTime;
        private ulong _lastUserTime;
        private ulong _lastIdleTime;
        private double _lastCpuPercent = double.NaN;

        private (double MemoryPressure, double CpuPressure, bool IsOnBattery) QueryCurrentPressure()
        {
            if (_pressureSampler != null) return _pressureSampler();
            double memPressure = double.NaN;
            double cpuPressure = _lastCpuPercent;
            bool isOnBattery = false;
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

                // Measure whole-system CPU load so the scanner yields to other applications.
                long now = Stopwatch.GetTimestamp();
                var elapsed = Stopwatch.GetElapsedTime(_lastCpuSampleTimestamp, now);
                if (elapsed.TotalMilliseconds > 500 || _lastKernelTime == 0)
                {
                    try
                    {
                        if (GetSystemTimes(out var idle, out var kernel, out var user))
                        {
                            ulong idleNow = ToUInt64(idle);
                            ulong kernelNow = ToUInt64(kernel);
                            ulong userNow = ToUInt64(user);
                            if (_lastKernelTime > 0 && kernelNow >= _lastKernelTime && userNow >= _lastUserTime && idleNow >= _lastIdleTime)
                            {
                                ulong kernelDelta = kernelNow - _lastKernelTime;
                                ulong userDelta = userNow - _lastUserTime;
                                ulong idleDelta = idleNow - _lastIdleTime;
                                ulong totalDelta = kernelDelta + userDelta;
                                if (totalDelta > 0)
                                {
                                    cpuPressure = Math.Clamp(100.0 * (totalDelta - Math.Min(idleDelta, totalDelta)) / totalDelta, 0, 100);
                                    _lastCpuPercent = cpuPressure;
                                }
                            }
                            _lastIdleTime = idleNow;
                            _lastKernelTime = kernelNow;
                            _lastUserTime = userNow;
                            _lastCpuSampleTimestamp = now;
                        }
                    }
                    catch (Exception ex) { _logger?.LogDebug(ex, "System CPU pressure query failed; the last sample is retained."); }
                }

                try
                {
                    isOnBattery = GetSystemPowerStatus(out var powerStatus) && powerStatus.ACLineStatus == 0;
                }
                catch (Exception ex) { _logger?.LogDebug(ex, "System power status query failed."); }
            }
            catch (Exception ex) { _logger?.LogDebug(ex, "System memory pressure query failed; conservative pressure is retained."); }
            return (memPressure, cpuPressure, isOnBattery);
        }

        private static ulong ToUInt64(NativeFileTime value) => ((ulong)value.High << 32) | value.Low;

        /// <summary>Changes the requested policy while retaining measured hardware and emergency-pressure limits.</summary>
        public void SetMode(ScanResourceMode mode)
        {
            lock (_lock)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (!Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
                if (_currentMode == mode) return;
                _currentMode = mode;
                if (mode == ScanResourceMode.Auto) _initialMeasuredPolicyReady = false;
                RebuildProfileInternal();
            }
        }

        /// <summary>Re-evaluates the actual target volume; unknown or remote storage remains conservatively seek-limited.</summary>
        public void ConfigureTarget(string targetPath)
        {
            bool isHdd = !_storageClassifier(ResolveStorageTarget(targetPath));
            lock (_lock)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                _mixedVolumes = false;
                _scanPressure.ConfigureTarget(ResolveStorageTarget(targetPath));
                if (_isHdd == isHdd) return;
                _isHdd = isHdd;
                RebuildProfileInternal();
            }
        }

        /// <inheritdoc />
        public void ConfigureMultipleVolumes()
        {
            lock (_lock)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                _mixedVolumes = true;
                _isHdd = false;
                RebuildProfileInternal();
            }
        }

        private static string ResolveStorageTarget(string? targetPath) => string.IsNullOrWhiteSpace(targetPath)
            ? Path.GetPathRoot(Environment.SystemDirectory) ?? Environment.SystemDirectory
            : targetPath;

        /// <summary>Samples live pressure for both automatic and manual policies, with hysteresis before automatic expansion.</summary>
        public void RefreshProfile()
        {
            lock (_lock)
            {
                if (_disposed) return;
                RebuildProfileInternal(allowHysteresis: true);
            }
        }

        private void RebuildProfileInternal(bool allowHysteresis = false)
        {
            var (memPressure, cpuPressure, isOnBattery) = QueryCurrentPressure();
            var newProfile = ScanResourceProfile.Create(
                _currentMode,
                _isHdd,
                _logicalCores,
                _totalRamBytes,
                cpuPressure,
                memPressure,
                isOnBattery);

            int oldConcurrency = _activeProfile.Concurrency;
            if (_pressureSampler == null || _workloadSampler != null)
                newProfile = ApplyMeasuredControl(newProfile, cpuPressure, allowHysteresis);
            int newConcurrency = newProfile.Concurrency;
            if (_pressureSampler != null && _workloadSampler == null && allowHysteresis && _currentMode == ScanResourceMode.Auto && newConcurrency > oldConcurrency)
            {
                _stableIncreaseSamples = _pendingIncrease?.SummaryText == newProfile.SummaryText ? _stableIncreaseSamples + 1 : 1;
                _pendingIncrease = newProfile;
                if (_stableIncreaseSamples < 3) return;
            }
            _pendingIncrease = null;
            _stableIncreaseSamples = 0;
            if (_activeProfile.Mode == newProfile.Mode && _activeProfile.SummaryText == newProfile.SummaryText) return;
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

        /// <summary>Waits cooperatively for a worker permit; manager disposal cancels pending waiters instead of stranding them.</summary>
        public async Task EnterWorkerSlotAsync(CancellationToken cancellationToken)
        {
            CancellationToken shutdown;
            lock (_lock)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                shutdown = _shutdownCancellation.Token;
                _waitingWorkers++;
            }
            try
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdown);
                while (ActiveProfile.IsAdmissionPaused) await Task.Delay(250, linked.Token);
                await _slotGate.WaitAsync(linked.Token);
                while (ActiveProfile.IsAdmissionPaused)
                {
                    ExitWorkerSlot();
                    while (ActiveProfile.IsAdmissionPaused) await Task.Delay(250, linked.Token);
                    await _slotGate.WaitAsync(linked.Token);
                }
            }
            finally
            {
                lock (_lock)
                {
                    _waitingWorkers--;
                    DisposeSlotGateIfDrained();
                }
            }
        }

        /// <summary>Returns a worker permit or absorbs it into an outstanding contraction deficit.</summary>
        public void ExitWorkerSlot()
        {
            lock (_lock)
            {
                if (_slotDeficit > 0)
                {
                    _slotDeficit--;
                    return;
                }
                if (!_disposed) _slotGate.Release();
            }
        }

        /// <summary>Applies cancellable pacing and cooperative yields; budgets do not authorize artificial RAM allocation.</summary>
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

        /// <summary>Stops telemetry and cancels queued workers; currently executing work must release its own permit.</summary>
        public void Dispose()
        {
            lock (_lock)
            {
                if (_disposed) return;
                _disposed = true;
                _telemetryTimer?.Dispose();
                _scanPressure.Dispose();
            }
            // Never run token callbacks while holding the profile lock.
            _shutdownCancellation.Cancel();
            lock (_lock) DisposeSlotGateIfDrained();
            _shutdownCancellation.Dispose();
        }

        private void DisposeSlotGateIfDrained()
        {
            // SemaphoreSlim.Dispose can erase its waiter list before asynchronous cancellation removes
            // those waiters. Keep the gate alive until their cancellation continuations have completed.
            if (!_disposed || _waitingWorkers != 0 || _slotGateDisposed) return;
            _slotGateDisposed = true;
            _slotGate.Dispose();
        }
    }
}
