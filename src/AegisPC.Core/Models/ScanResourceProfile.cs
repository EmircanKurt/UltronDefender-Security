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
            ScanResourceMode mode,
            bool isHdd,
            int logicalCores,
            long totalRamBytes,
            double cpuPressurePercent = 0,
            double memoryPressurePercent = 0,
            bool isOnBattery = false)
        {
            int cores = Math.Max(1, logicalCores);
            if (!Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
            long measuredRamBytes = totalRamBytes > 0 ? totalRamBytes : 512L * 1024 * 1024;
            long ramMb = Math.Max(1, measuredRamBytes / (1024 * 1024));
            memoryPressurePercent = double.IsFinite(memoryPressurePercent)
                ? Math.Clamp(memoryPressurePercent, 0, 100) : 88;
            cpuPressurePercent = double.IsFinite(cpuPressurePercent)
                ? Math.Clamp(cpuPressurePercent, 0, 100) : 78;

            // Auto mode uses whole-system pressure and battery state, not only the scanner's
            // own CPU usage. Keep small and memory-constrained computers on a conservative path.
            ScanResourceMode effectiveMode = mode;
            if (mode == ScanResourceMode.Auto)
            {
                if (memoryPressurePercent >= 88.0 || (cores <= 2 && ramMb < 8192))
                {
                    effectiveMode = ScanResourceMode.VeryLow;
                }
                else if (isOnBattery || memoryPressurePercent >= 78.0 || cpuPressurePercent >= 78.0)
                {
                    effectiveMode = ScanResourceMode.Low;
                }
                // A nominal 16 GiB computer reports slightly less usable physical RAM after
                // firmware/hardware reservations. Classify the tier with tolerance only;
                // actual memory limits below still use the measured bytes and free headroom.
                else if (!isHdd && cores >= 8 && ramMb >= 15_360 && cpuPressurePercent < 35.0 && memoryPressurePercent < 65.0)
                {
                    effectiveMode = ScanResourceMode.High;
                }
                else
                {
                    effectiveMode = ScanResourceMode.Balanced;
                }
            }

            int concurrency;
            int delayMs;
            int yieldFreq;
            long memoryBudgetMb;
            int queueCapacity;

            switch (effectiveMode)
            {
                case ScanResourceMode.VeryLow:
                    concurrency = 1;
                    delayMs = 10;
                    yieldFreq = 10;
                    memoryBudgetMb = Math.Clamp(ramMb / 16, 64, 128);
                    queueCapacity = 256;
                    break;

                case ScanResourceMode.Low:
                    // Low-end/battery mode: don't create more workers than useful cores.
                    concurrency = Math.Clamp(cores / 2, 2, Math.Max(2, cores / 2));
                    delayMs = 2;
                    yieldFreq = 50;
                    memoryBudgetMb = Math.Min(512, Math.Max(256, ramMb / 12));
                    queueCapacity = 512;
                    break;

                case ScanResourceMode.High:
                    // 🚀 Yüksek: Modern çok çekirdekli sistemlerde agresif ama dengeli paralellik (cores * 3)
                    concurrency = Math.Max(4, cores * 3);
                    delayMs = 0;
                    yieldFreq = 0;
                    memoryBudgetMb = Math.Max(3072, (long)(ramMb / 2.0));
                    queueCapacity = 65536;
                    break;

                case ScanResourceMode.Maximum:
                    // 🚀 Tam Güç: NVMe SSD ve tüm çekirdek kapasitesini tam doyuran maksimum verim (cores * 4)
                    concurrency = Math.Max(cores, cores * 4);
                    delayMs = 0;
                    yieldFreq = 0;
                    memoryBudgetMb = Math.Max(4096, (long)(ramMb / 1.5));
                    queueCapacity = 65536;
                    break;

                case ScanResourceMode.Balanced:
                default:
                    // ⚖️ Dengeli: Yeterli I/O doyumu (cores * 2), sıfır yapay gecikme
                    concurrency = Math.Max(2, cores * 2);
                    delayMs = 0;
                    yieldFreq = 0;
                    memoryBudgetMb = Math.Min(2048, Math.Max(256, (long)(ramMb / 3.0)));
                    queueCapacity = 2048;
                    break;
            }

            // HDD koruma: mekanik disk head-thrashing'i önle ama CPU tarafını boşa harcama
            bool hddCapped = false;
            if (isHdd)
            {
                // HDD'de disk I/O kafa atlamalarını önle
                concurrency = Math.Clamp(concurrency, 1, Math.Min(2, cores));
                delayMs = Math.Max(delayMs, 2);
                hddCapped = true;
            }

            // Selected profiles still obey machine limits. Manual Maximum requests must not
            // create dozens of simultaneous hash/PE/YARA pipelines on a small CPU or RAM budget.
            int hardwareConcurrencyCap = cores <= 2 ? cores : Math.Min(64, cores * 4);
            concurrency = Math.Clamp(concurrency, 1, hardwareConcurrencyCap);
            long profileMemoryCapMb = Math.Max(1, Math.Min(ramMb * 3 / 5, 16384));
            memoryBudgetMb = Math.Min(memoryBudgetMb, profileMemoryCapMb);
            queueCapacity = Math.Clamp(queueCapacity, 256, 65536);

            // Minimum RAM bütçesi: VeryLow için en fazla 128 MB, diğerleri için en az 256 MB
            memoryBudgetMb = effectiveMode == ScanResourceMode.VeryLow 
                ? Math.Clamp(memoryBudgetMb, 64, 128)
                : Math.Min(profileMemoryCapMb, Math.Max(256, memoryBudgetMb));
            // Even manual Maximum must yield when physical memory is already exhausted.
            if (memoryPressurePercent >= 88)
            {
                concurrency = 1;
                memoryBudgetMb = Math.Min(memoryBudgetMb, 128);
                queueCapacity = 256;
            }

            // Leave a quarter of currently available RAM for real-time protection and the OS.
            // This final cap also overrides historical minimum budgets on genuinely small devices.
            long availableBudgetMb = Math.Max(1, (long)(ramMb * (100 - memoryPressurePercent) / 100 * 0.75));
            memoryBudgetMb = Math.Min(memoryBudgetMb, Math.Min(profileMemoryCapMb, availableBudgetMb));
            // Reserve headroom per simultaneous hash/PE/YARA pipeline, even on many-core machines.
            concurrency = Math.Min(concurrency, Math.Max(1, (int)(memoryBudgetMb / 64)));
            if (memoryBudgetMb < 256)
            {
                concurrency = Math.Min(concurrency, Math.Max(1, (int)(memoryBudgetMb / 64)));
                queueCapacity = Math.Min(queueCapacity, 512);
            }

            long totalRamGb = (long)Math.Round((double)totalRamBytes / (1024.0 * 1024.0 * 1024.0));
            if (totalRamGb < 1) totalRamGb = 1;
            double budgetGb = (double)memoryBudgetMb / 1024.0;
            string ramText = budgetGb >= 1.0 
                ? $"{totalRamGb} GB RAM'in ~{budgetGb:0.#} GB'ı kullanılabilir" 
                : $"{totalRamGb} GB RAM'in ~{memoryBudgetMb} MB'ı kullanılabilir";

            string modePrefix = effectiveMode switch
            {
                ScanResourceMode.Low => "🌱 Sakin",
                ScanResourceMode.Balanced => "⚖️ Dengeli",
                ScanResourceMode.Maximum => "🚀 Tam Güç",
                ScanResourceMode.High => "🚀 Yüksek",
                ScanResourceMode.VeryLow => "🌱 Çok Düşük",
                _ => effectiveMode.ToString()
            };

            string summary = $"{modePrefix} ({concurrency} İş Parçacığı • {ramText}" +
                             (delayMs > 0 ? $" • {delayMs}ms Gecikme" : string.Empty) +
                             (hddCapped ? " • HDD Korumalı" : string.Empty) + ")";

            return new ScanResourceProfile
            {
                Mode = mode,
                Concurrency = concurrency,
                ChannelCapacity = queueCapacity,
                BatchSize = Math.Max(50, queueCapacity / 16),
                DelayBetweenFilesMs = delayMs,
                YieldFrequency = yieldFreq,
                MaxMemoryBudgetBytes = memoryBudgetMb * 1024 * 1024,
                IsHddRestricted = hddCapped,
                SummaryText = summary
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
