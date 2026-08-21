using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Recommendations.Rules
{
    public static class StabilityRule
    {
        public static async Task<List<Recommendation>> EvaluateAsync(
            ICrashAnalyzer? crashAnalyzer,
            CancellationToken cancellationToken = default)
        {
            var list = new List<Recommendation>();

            if (crashAnalyzer != null)
            {
                var crashes = await crashAnalyzer.GetRecentCrashesAsync(TimeSpan.FromDays(3), cancellationToken);

                // Group crashes by application
                var grouped = crashes.GroupBy(c => c.ApplicationName).Where(g => g.Count() >= 2).ToList();
                foreach (var group in grouped)
                {
                    list.Add(new Recommendation
                    {
                        Category = RecommendationCategory.Stability,
                        Title = $"Tekrarlayan Uygulama Çökmesi: {group.Key}",
                        Description = $"'{group.Key}' uygulaması son 3 gün içinde {group.Count()} kez çöktü veya dondu.",
                        Reasoning = "Sık çöken uygulamalar kararsız sürücüler, bozuk yapılandırma dosyaları veya bellek sızıntılarından kaynaklanabilir.",
                        RiskLevel = RiskLevel.LowRisk,
                        EstimatedImpact = ImpactLevel.Medium,
                        ActionType = "NavigateToCrashAnalysis"
                    });
                }
            }

            return list;
        }
    }
}
