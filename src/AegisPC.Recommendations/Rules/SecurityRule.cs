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
    public static class SecurityRule
    {
        public static async Task<List<Recommendation>> EvaluateAsync(
            ISecurityFindingService? findingService,
            IBrowserSecurityScanner? browserScanner,
            CancellationToken cancellationToken = default)
        {
            var list = new List<Recommendation>();

            if (findingService != null)
            {
                var findings = await findingService.GetAllFindingsAsync(cancellationToken);
                var activeFindings = findings.Where(f => f.Status == FindingStatus.Active).ToList();

                if (activeFindings.Count > 0)
                {
                    int highRisk = activeFindings.Count(f => f.RiskLevel == RiskLevel.HighRisk);
                    list.Add(new Recommendation
                    {
                        Category = RecommendationCategory.Security,
                        Title = $"{activeFindings.Count} Adet Güvenlik İncelemesi Bekleyen Dosya",
                        Description = highRisk > 0 
                            ? $"{highRisk} tanesi yüksek riskli olmak üzere incelenmeyi bekleyen bulgular var. Karantinaya alabilir veya güvenli olarak işaretleyebilirsiniz."
                            : "Sistemde şüpheli davranış veya anomali gösteren dosyalar tespit edildi.",
                        Reasoning = "Riskli dosyaların karantinaya alınması yetkisiz kod yürütülmesini engeller.",
                        RiskLevel = highRisk > 0 ? RiskLevel.HighRisk : RiskLevel.Suspicious,
                        EstimatedImpact = ImpactLevel.High,
                        ActionType = "NavigateToSecurity"
                    });
                }
            }

            if (browserScanner != null)
            {
                var profiles = await browserScanner.ScanAllBrowsersAsync(cancellationToken);
                var allExt = profiles.SelectMany(p => p.Extensions).ToList();
                var sideloaded = allExt.Where(e => e.IsSideloaded && e.RiskLevel >= RiskLevel.Suspicious).ToList();

                if (sideloaded.Count > 0)
                {
                    list.Add(new Recommendation
                    {
                        Category = RecommendationCategory.Privacy,
                        Title = "Harici Kaynaktan Yüklenmiş Tarayıcı Eklentisi",
                        Description = $"'{sideloaded[0].Name}' resmi mağaza dışından yüklenmiş ve geniş web izinleri talep ediyor.",
                        Reasoning = "Doğrulanmamış eklentiler gezinme verilerinizi toplayabilir veya tarayıcı trafiğinizi yönlendirebilir.",
                        RiskLevel = RiskLevel.Suspicious,
                        EstimatedImpact = ImpactLevel.Medium,
                        ActionType = "NavigateToBrowserSecurity"
                    });
                }
            }

            return list;
        }
    }
}
