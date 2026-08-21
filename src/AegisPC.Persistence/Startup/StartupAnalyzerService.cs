using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Persistence.Startup
{
    public class StartupAnalyzerService : IStartupAnalyzer
    {
        private readonly ILogger<StartupAnalyzerService>? _logger;

        public StartupAnalyzerService(ILogger<StartupAnalyzerService>? logger = null)
        {
            _logger = logger;
        }

        public Task<List<StartupItem>> GetStartupItemsAsync(CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                var items = new List<StartupItem>();

                // 1. Registry
                items.AddRange(RegistryStartupScanner.ScanRegistryStartup());

                // 2. Startup Folders
                items.AddRange(StartupFolderScanner.ScanStartupFolders());

                // 3. Logon Scheduled Tasks
                items.AddRange(TaskSchedulerScanner.ScanLogonTasks());

                // Assess risk for each item
                foreach (var item in items)
                {
                    if (string.IsNullOrEmpty(item.FilePath)) continue;

                    if (PathHelper.IsTempPath(item.FilePath))
                    {
                        item.RiskLevel = RiskLevel.HighRisk;
                    }
                    else if (item.FilePath.Contains("AppData\\Local\\Temp", StringComparison.OrdinalIgnoreCase))
                    {
                        item.RiskLevel = RiskLevel.Suspicious;
                    }
                }

                return items;
            }, cancellationToken);
        }

        public async Task<List<Recommendation>> AnalyzeStartupImpactAsync(CancellationToken cancellationToken = default)
        {
            var items = await GetStartupItemsAsync(cancellationToken);
            var recommendations = new List<Recommendation>();

            if (items.Count > 10)
            {
                recommendations.Add(new Recommendation
                {
                    Category = RecommendationCategory.Startup,
                    Title = "Yüksek Başlangıç Uygulaması Sayısı",
                    Description = $"Sistem açılışında otomatik başlayan {items.Count} uygulama tespit edildi. Bu durum Windows açılış süresini uzatabilir.",
                    Reasoning = "Gereksiz başlangıç programlarını devre dışı bırakmak açılış hızını ve boş RAM miktarını artırır.",
                    RiskLevel = RiskLevel.LowRisk,
                    EstimatedImpact = ImpactLevel.High
                });
            }

            foreach (var item in items)
            {
                if (item.RiskLevel >= RiskLevel.Suspicious)
                {
                    recommendations.Add(new Recommendation
                    {
                        Category = RecommendationCategory.Security,
                        Title = $"Şüpheli Başlangıç Girdisi: {item.Name}",
                        Description = $"'{item.FilePath}' konumundaki başlangıç girdisi güvenli olmayan bir dizinde bulunuyor.",
                        Reasoning = "Geçici dizinlerden başlayan programlar zararlı yazılım kalıcılık taktiği olabilir.",
                        RiskLevel = item.RiskLevel,
                        EstimatedImpact = ImpactLevel.High
                    });
                }
            }

            return recommendations;
        }
    }
}
