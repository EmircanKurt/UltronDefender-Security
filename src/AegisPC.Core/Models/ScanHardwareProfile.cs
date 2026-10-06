using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;

namespace AegisPC.Core.Models
{
    /// <summary>
    /// Presents the same measured-capacity adaptive limits used by the scan resource manager.
    /// This snapshot is not a synthetic benchmark and does not promise a fixed CPU or RAM utilization percentage.
    /// </summary>
    public class ScanHardwareProfile
    {
        /// <summary>Gets or sets detected physical memory capacity in binary gigabytes.</summary>
        public double TotalRamGb { get; set; }
        /// <summary>Gets or sets the logical processors available to this process.</summary>
        public int CpuCores { get; set; }
        /// <summary>Gets or sets the calculated scan working-set budget, not preallocated RAM or a process RSS guarantee.</summary>
        public long MaxMemoryBudgetBytes { get; set; }
        /// <summary>Gets the actual calculated budget in binary megabytes.</summary>
        public int MaxMemoryBudgetMb => (int)(MaxMemoryBudgetBytes / (1024 * 1024));
        /// <summary>Gets or sets the hardware- and pressure-capped worker count.</summary>
        public int Concurrency { get; set; }
        /// <summary>Gets or sets the presentation label for this adaptive snapshot.</summary>
        public string ProfileName { get; set; } = string.Empty;
        private string _summaryText = string.Empty;
        /// <summary>Gets or sets the active-scan summary source; when absent, the initial snapshot is displayed.</summary>
        public static Func<string>? ActiveSummaryProvider { get; set; }

        /// <summary>Gets the live profile summary when available, otherwise the measured startup snapshot.</summary>
        public string SummaryText
        {
            get => ActiveSummaryProvider?.Invoke() ?? _summaryText;
            set => _summaryText = value;
        }

        /// <summary>
        /// Detects RAM and the system-volume seek penalty without writing benchmark files or guessing SSD capabilities.
        /// Unknown storage uses the rotational policy and target scans may subsequently configure their own actual volume.
        /// </summary>
        public static ScanHardwareProfile Detect() => Detect(
            DiskHardwareHelper.IsSolidStateDrive(Path.GetPathRoot(Environment.SystemDirectory)));

        /// <summary>Creates a measured-RAM snapshot for an explicitly known SSD or seek-limited target volume.</summary>
        public static ScanHardwareProfile Detect(bool isSsd)
        {
            var memory = QueryMemoryCapacity();
            long totalRamBytes = memory.TotalBytes;
            double ramGb = totalRamBytes / (1024.0 * 1024.0 * 1024.0);
            int cores = Math.Max(1, Environment.ProcessorCount);
            var profile = ScanResourceProfile.Create(ScanResourceMode.Auto, !isSsd, cores,
                totalRamBytes, memoryPressurePercent: memory.Pressure);

            return new ScanHardwareProfile
            {
                TotalRamGb = ramGb,
                CpuCores = cores,
                MaxMemoryBudgetBytes = profile.MaxMemoryBudgetBytes,
                Concurrency = profile.Concurrency,
                ProfileName = "Otomatik Donanım Profili",
                SummaryText = profile.SummaryText
            };
        }

        private static (long TotalBytes, double Pressure) QueryMemoryCapacity()
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    var memory = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
                    if (GlobalMemoryStatusEx(ref memory) && memory.TotalPhysical > 0 && memory.TotalPhysical <= long.MaxValue)
                        return ((long)memory.TotalPhysical, memory.Load);
                }
            }
            catch (Exception ex) { Trace.TraceWarning("Startup physical memory query failed: {0}", ex.Message); }
            long runtimeCapacity = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
            return (runtimeCapacity > 0 ? runtimeCapacity : 512L * 1024 * 1024, 50);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MemoryStatus
        {
            public uint Length;
            public uint Load;
            public ulong TotalPhysical;
            public ulong AvailablePhysical;
            public ulong TotalPageFile;
            public ulong AvailablePageFile;
            public ulong TotalVirtual;
            public ulong AvailableVirtual;
            public ulong AvailableExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MemoryStatus memory);
    }
}
