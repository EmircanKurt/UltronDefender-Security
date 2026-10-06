using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models
{
    /// <summary>
    /// Encapsulates concrete resource limits and concurrency parameters for scan execution.
    /// Governs worker counts, memory budgets, queue capacities, and cooperative throttling.
    /// Resource budgets are derived from measured RAM, logical processors, storage policy, and current system pressure.
    /// </summary>
    public class ScanResourceProfile
    {
        /// <summary>Gets the requested policy; Auto retains its identity when the effective limits change.</summary>
        public ScanResourceMode Mode { get; init; }
        /// <summary>Gets the maximum simultaneous file-analysis workers permitted by this policy.</summary>
        public int Concurrency { get; init; }
        /// <summary>Measured-hardware ceiling; Auto grows toward it only while throughput and pressure permit.</summary>
        public int MaximumConcurrency { get; init; }
        /// <summary>Cooperative scanner-process CPU target, not an operating-system hard reservation.</summary>
        public double CpuTargetPercent { get; init; } = 40;
        /// <summary>Explains the current contraction or conservative fallback.</summary>
        public string LimitingReason { get; init; } = string.Empty;
        /// <summary>Defers new heavy analyses during critical measured memory pressure; existing work can finish.</summary>
        public bool IsAdmissionPaused { get; init; }
        /// <summary>Gets the bounded pending-file queue capacity, not a file-content allocation allowance.</summary>
        public int ChannelCapacity { get; init; }
        /// <summary>Gets the suggested number of queue entries per cooperative producer batch.</summary>
        public int BatchSize { get; init; }
        /// <summary>Gets the cancellable pacing delay applied between individual file analyses.</summary>
        public int DelayBetweenFilesMs { get; init; }
        /// <summary>Gets the number of processed files between cooperative yields; zero disables periodic yields.</summary>
        public int YieldFrequency { get; init; }
        /// <summary>Gets a scan working-set budget, capped by physical and available RAM; this is not a process RSS guarantee.</summary>
        public long MaxMemoryBudgetBytes { get; init; }
        /// <summary>Gets whether conservative seek-penalty limits are active for rotational or unknown storage.</summary>
        public bool IsHddRestricted { get; init; }
        /// <summary>Gets the invariant name of the requested policy for settings and telemetry.</summary>
        public string Name => Mode.ToString();
        /// <summary>Gets a user-facing summary derived from the actual calculated limits.</summary>
        public string SummaryText { get; init; } = string.Empty;

        /// <summary>
        /// Calculates bounded worker and memory limits from measured hardware and current pressure.
        /// Invalid capacity readings use a conservative fallback; no RAM or CPU is consumed to fill a target percentage.
        /// </summary>
        public static ScanResourceProfile Create(
            ScanResourceMode mode, bool isHdd, int logicalCores, long totalRamBytes,
            double cpuPressurePercent = 0, double memoryPressurePercent = 0, bool isOnBattery = false)
        {
            if (!Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
            int cores = Math.Max(1, logicalCores);
            long ramMb = Math.Max(1, (totalRamBytes > 0 ? totalRamBytes : 512L * 1024 * 1024) / 1048576);
            bool available = double.IsFinite(memoryPressurePercent) && double.IsFinite(cpuPressurePercent);
            double memory = available ? Math.Clamp(memoryPressurePercent, 0, 100) : 88;
            double cpu = available ? Math.Clamp(cpuPressurePercent, 0, 100) : 78;
            long tierMb = ramMb <= 4096 ? 256 : ramMb <= 8192 ? 512 : ramMb < 15360 ? 1024 : 2048;
            long reserveMb = Math.Max(512, ramMb / 10);
            long freeMb = (long)(ramMb * (100 - memory) / 100);
            long budgetMb = Math.Max(1, Math.Min(tierMb, freeMb - reserveMb));
            int maximum = isHdd ? Math.Min(2, cores) : cores <= 2 ? cores : Math.Min(24, cores * 2);
            int workers = mode switch
            {
                ScanResourceMode.VeryLow => 1,
                ScanResourceMode.Low => Math.Min(2, maximum),
                ScanResourceMode.Balanced => Math.Min(4, maximum),
                ScanResourceMode.High => Math.Min(8, maximum),
                ScanResourceMode.Maximum => maximum,
                _ => isHdd ? 1 : Math.Min(4, maximum)
            };
            string reason = string.Empty;
            if (mode == ScanResourceMode.VeryLow) budgetMb = Math.Min(budgetMb, 128);
            if (mode == ScanResourceMode.Low) budgetMb = Math.Min(budgetMb, 512);
            if (isOnBattery || cpu >= 70 || memory >= 85 || !available)
            {
                workers = Math.Min(workers, 2);
                maximum = Math.Min(maximum, 2);
                reason = !available ? "Ölçüm eksik" : isOnBattery ? "Pil kullanımı" : memory >= 85 ? "Bellek baskısı" : "İşlemci yükü";
            }
            if (memory >= 92 || budgetMb < 64)
            {
                workers = maximum = 1;
                budgetMb = Math.Min(budgetMb, 128);
                reason = "Kritik bellek baskısı";
            }
            maximum = Math.Min(maximum, Math.Max(1, (int)(budgetMb / 64)));
            workers = Math.Clamp(workers, 1, Math.Max(1, maximum));
            int delay = mode == ScanResourceMode.VeryLow || memory >= 92 ? 10 : mode == ScanResourceMode.Low ? 2 : 0;
            string summary = $"Sistem Gereksinimleri • {mode} • {workers} işçi • RAM bütçesi {budgetMb:N0} MiB • CPU hedefi ~%40";
            if (isHdd) summary += " • HDD/Belirsiz disk";
            if (reason.Length > 0) summary += " • " + reason;
            return new ScanResourceProfile
            {
                Mode = mode, Concurrency = workers, MaximumConcurrency = maximum,
                ChannelCapacity = mode == ScanResourceMode.VeryLow ? 256 : 1024,
                BatchSize = 64, DelayBetweenFilesMs = delay, YieldFrequency = delay > 0 ? 10 : 0,
                MaxMemoryBudgetBytes = budgetMb * 1048576, IsHddRestricted = isHdd,
                CpuTargetPercent = 40, LimitingReason = reason, SummaryText = summary,
                IsAdmissionPaused = available && memory >= 92
            };
        }

        /// <summary>Creates the initial adaptive policy from runtime-detected capacity without a synthetic speed benchmark.</summary>
        public static ScanResourceProfile CreateDefault(ScanResourceMode mode = ScanResourceMode.Auto)
        {
            long totalRam = (long)GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
            if (totalRam <= 0) totalRam = 512L * 1024 * 1024;
            return Create(mode, false, Environment.ProcessorCount, totalRam);
        }
    }
}
