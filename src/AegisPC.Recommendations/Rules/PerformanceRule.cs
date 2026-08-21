using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Recommendations.Rules
{
    public static class PerformanceRule
    {
        public static async Task<List<Recommendation>> EvaluateAsync(
            IPerformanceMonitor? performanceMonitor,
            CancellationToken cancellationToken = default)
        {
            var list = new List<Recommendation>();

            if (performanceMonitor != null)
            {
                var sample = await performanceMonitor.GetCurrentSampleAsync();

                // High CPU
                if (sample.CpuPercent > 80.0)
                {
                    list.Add(new Recommendation
                    {
                        Category = RecommendationCategory.Performance,
                        Title = "Yüksek İşlemci (CPU) Kullanımı",
                        Description = $"Sistem işlemci yükü %{sample.CpuPercent:F1} seviyesinde. Arka planda kaynak tüketen süreçleri inceleyin.",
                        Reasoning = "Gereksiz yüksek CPU kullanımı pil ömrünü kısaltır ve sistem tepki süresini yavaşlatır.",
                        RiskLevel = RiskLevel.LowRisk,
                        EstimatedImpact = ImpactLevel.Medium,
                        ActionType = "NavigateToProcesses"
                    });
                }

                // Low Disk Free Space (<10% or <15GB on C:)
                try
                {
                    var cDrive = DriveInfo.GetDrives().FirstOrDefault(d => d.IsReady && d.Name.StartsWith("C", StringComparison.OrdinalIgnoreCase));
                    if (cDrive != null)
                    {
                        double freeGb = cDrive.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0);
                        if (freeGb < 15.0)
                        {
                            list.Add(new Recommendation
                            {
                                Category = RecommendationCategory.Storage,
                                Title = "Sistem Diskinde Düşük Boş Alan (C:)",
                                Description = $"C: sürücünüzde yalnızca {freeGb:F1} GB boş alan kaldı.",
                                Reasoning = "Düşük disk alanı Windows güncellemelerinin başarısız olmasına ve sanal bellek darboğazlarına yol açabilir.",
                                RiskLevel = RiskLevel.LowRisk,
                                EstimatedImpact = ImpactLevel.High,
                                ActionType = "NavigateToPerformance"
                            });
                        }
                    }
                }
                catch { }
            }

            return list;
        }
    }
}
