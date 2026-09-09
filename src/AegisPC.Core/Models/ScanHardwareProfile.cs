using System;

namespace AegisPC.Core.Models
{
    /// <summary>
    /// Tarama öncesi otomatik sistem donanımı tespiti ve adaptif kaynak sınırları profili.
    /// RAM miktarına orantılı bellek tavanı ve CPU çekirdeklerine göre paralel işçi tahsisi sağlar.
    /// </summary>
    public class ScanHardwareProfile
    {
        public double TotalRamGb { get; set; }
        public int CpuCores { get; set; }
        public long MaxMemoryBudgetBytes { get; set; }
        public int MaxMemoryBudgetMb => (int)(MaxMemoryBudgetBytes / (1024 * 1024));
        public int Concurrency { get; set; }
        public string ProfileName { get; set; } = string.Empty;
        private string _summaryText = string.Empty;
        public static Func<string>? ActiveSummaryProvider { get; set; }

        public string SummaryText
        {
            get => ActiveSummaryProvider?.Invoke() ?? _summaryText;
            set => _summaryText = value;
        }

        /// <summary>
        /// Mevcut sistemin fiziksel RAM ve CPU çekirdeklerini otomatik tespit ederek
        /// optimum kaynak profilini hesaplar. RAM'in %50'si tarama bütçesi olarak tahsis edilir.
        /// </summary>
        public static ScanHardwareProfile Detect(bool isSsd = true)
        {
            double totalRamBytes = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
            if (totalRamBytes <= 0)
            {
                totalRamBytes = 8.0 * 1024 * 1024 * 1024; // 8GB default fallback
            }
            double ramGb = totalRamBytes / (1024.0 * 1024.0 * 1024.0);
            int cores = Environment.ProcessorCount;

            // RAM bütçesi: sistemin toplam RAM'inin %50'si (her zaman orantılı)
            long budgetBytes;
            int workers;
            string name;

            if (ramGb <= 4.5)
            {
                budgetBytes = (long)(totalRamBytes / 3);
                workers = isSsd ? Math.Max(2, cores - 1) : Math.Max(1, cores / 2);
                name = "Hafif Sistem (Orantılı Mod)";
            }
            else if (ramGb <= 10.0)
            {
                budgetBytes = (long)(totalRamBytes / 2);
                workers = isSsd ? Math.Max(4, cores - 1) : Math.Max(2, cores / 2);
                name = "Standart Sistem (Yüksek Performans)";
            }
            else
            {
                budgetBytes = (long)(totalRamBytes / 2);
                workers = isSsd ? Math.Max(4, cores - 1) : Math.Max(2, cores / 2);
                name = "Güçlü Sistem (Maksimum Performans)";
            }

            if (cores > 1)
            {
                workers = Math.Max(1, Math.Min(workers, cores - 1));
            }

            var defaultProfile = ScanResourceProfile.CreateDefault();
            string summary = defaultProfile.SummaryText;

            return new ScanHardwareProfile
            {
                TotalRamGb = ramGb,
                CpuCores = cores,
                MaxMemoryBudgetBytes = budgetBytes,
                Concurrency = workers,
                ProfileName = name,
                SummaryText = summary
            };
        }
    }
}
