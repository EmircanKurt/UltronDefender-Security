using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models
{
    /// <summary>
    /// Encapsulates concrete resource limits and concurrency parameters for scan execution.
    /// Governs worker counts, memory budgets, queue capacities, and cooperative throttling.
    /// Kaynak bütçeleri sistemin gerçek donanımına (RAM, CPU çekirdekleri) oranlanır.
    /// </summary>
    public class ScanResourceProfile
    {
        public ScanResourceMode Mode { get; init; }
        public int Concurrency { get; init; }
        public int ChannelCapacity { get; init; }
        public int BatchSize { get; init; }
        public int DelayBetweenFilesMs { get; init; }
        public int YieldFrequency { get; init; }
        public long MaxMemoryBudgetBytes { get; init; }
        public bool IsHddRestricted { get; init; }
        public string Name => Mode.ToString();
        public string SummaryText { get; init; } = string.Empty;

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
            long ramMb = Math.Max(512, totalRamBytes / (1024 * 1024));

            // If Auto, calculate target effective mode based on live telemetry
            ScanResourceMode effectiveMode = mode;
            if (mode == ScanResourceMode.Auto)
            {
                if (isOnBattery)
                {
                    effectiveMode = ScanResourceMode.Low;
                }
                else if (memoryPressurePercent > 90.0)
                {
                    effectiveMode = ScanResourceMode.VeryLow;
                }
                else if (cores >= 4 && ramMb >= 6000)
                {
                    // 8 GB / 16 GB ve üzeri sistemlerde tarama en yüksek performansta (High) çalışır
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
                    delayMs = 15;
                    yieldFreq = 5;
                    memoryBudgetMb = Math.Min(128, Math.Max(64, ramMb / 16));
                    queueCapacity = 2048;
                    break;

                case ScanResourceMode.Low:
                    // 🌱 Sakin: ~1 GB RAM, düşük CPU
                    concurrency = Math.Max(2, Math.Min(4, cores / 2));
                    delayMs = 5;
                    yieldFreq = 25;
                    memoryBudgetMb = Math.Min(1024, Math.Max(256, ramMb / 4));
                    queueCapacity = 4096;
                    break;

                case ScanResourceMode.High:
                    concurrency = Math.Max(4, cores * 2);
                    delayMs = 0;
                    yieldFreq = 0;
                    memoryBudgetMb = Math.Max(512, (long)(ramMb / 2.0));
                    queueCapacity = 65536;
                    break;

                case ScanResourceMode.Maximum:
                    // 🚀 Tam Güç: Tüm çekirdekler ve yüksek RAM bütçesi
                    concurrency = Math.Max(Environment.ProcessorCount, cores * 2);
                    delayMs = 0;
                    yieldFreq = 0;
                    memoryBudgetMb = Math.Max(1024, (long)(ramMb * 0.75));
                    queueCapacity = 65536;
                    break;

                case ScanResourceMode.Balanced:
                default:
                    // ⚖️ Dengeli: RAM'in 1/3'ü, dengeli CPU
                    concurrency = Math.Max(2, cores);
                    delayMs = 0;
                    yieldFreq = 0;
                    memoryBudgetMb = Math.Max(256, (long)(ramMb / 3.0));
                    queueCapacity = 32768;
                    break;
            }

            // HDD koruma: mekanik disk head-thrashing'i önle ama CPU tarafını boşa harcama
            bool hddCapped = false;
            if (isHdd)
            {
                // HDD'de disk I/O zaten darboğaz, ama CPU işlemleri paralel yapılabilir
                concurrency = Math.Max(2, Math.Min(concurrency, Math.Max(cores / 2, 2)));
                delayMs = Math.Max(delayMs, 2);
                hddCapped = true;
            }

            // Minimum RAM bütçesi: VeryLow için 128 MB, diğerleri için en az 256 MB
            memoryBudgetMb = effectiveMode == ScanResourceMode.VeryLow 
                ? Math.Min(256, Math.Max(64, memoryBudgetMb))
                : Math.Max(256, memoryBudgetMb);

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

        public static ScanResourceProfile CreateDefault(ScanResourceMode mode = ScanResourceMode.Balanced)
        {
            long totalRam = (long)GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
            if (totalRam <= 0) totalRam = 8L * 1024 * 1024 * 1024;
            return Create(mode, false, Environment.ProcessorCount, totalRam);
        }
    }
}
