using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Recommendations.Engine
{
    public class HealthScoringEngine
    {
        private readonly ISecurityFindingService? _findingService;
        private readonly IPerformanceMonitor? _performanceMonitor;
        private readonly ICrashAnalyzer? _crashAnalyzer;
        private readonly IStartupAnalyzer? _startupAnalyzer;
        private readonly IBrowserSecurityScanner? _browserScanner;

        public HealthScoringEngine(
            ISecurityFindingService? findingService = null,
            IPerformanceMonitor? performanceMonitor = null,
            ICrashAnalyzer? crashAnalyzer = null,
            IStartupAnalyzer? startupAnalyzer = null,
            IBrowserSecurityScanner? browserScanner = null)
        {
            _findingService = findingService;
            _performanceMonitor = performanceMonitor;
            _crashAnalyzer = crashAnalyzer;
            _startupAnalyzer = startupAnalyzer;
            _browserScanner = browserScanner;
        }

        public async Task<HealthScore> CalculateHealthScoreAsync(CancellationToken cancellationToken = default)
        {
            int securityScore = 100;
            int perfScore = 90;
            int stabilityScore = 100;
            int startupScore = 95;
            int browserScore = 100;
            int activeFindings = 0;
            int recentCrashes = 0;

            // Security score calculation
            if (_findingService != null)
            {
                var findings = await _findingService.GetAllFindingsAsync(cancellationToken);
                var active = findings.Where(f => f.Status == FindingStatus.Active).ToList();
                activeFindings = active.Count;

                int high = active.Count(f => f.RiskLevel == RiskLevel.HighRisk);
                int susp = active.Count(f => f.RiskLevel == RiskLevel.Suspicious);
                int low = active.Count(f => f.RiskLevel == RiskLevel.LowRisk);

                securityScore -= (high * 30) + (susp * 15) + (low * 5);
                securityScore = Math.Clamp(securityScore, 10, 100);
            }

            // Performance score calculation
            if (_performanceMonitor != null)
            {
                var sample = await _performanceMonitor.GetCurrentSampleAsync();
                if (sample.CpuPercent > 80) perfScore -= 20;
                else if (sample.CpuPercent > 60) perfScore -= 10;

                if (sample.DiskUsagePercent > 90) perfScore -= 15;
                perfScore = Math.Clamp(perfScore, 20, 100);
            }

            // Stability score calculation
            if (_crashAnalyzer != null)
            {
                var crashes = await _crashAnalyzer.GetRecentCrashesAsync(TimeSpan.FromDays(3), cancellationToken);
                recentCrashes = crashes.Count;
                stabilityScore -= crashes.Count * 10;
                stabilityScore = Math.Clamp(stabilityScore, 20, 100);
            }

            // Startup score calculation
            if (_startupAnalyzer != null)
            {
                var startupItems = await _startupAnalyzer.GetStartupItemsAsync(cancellationToken);
                if (startupItems.Count > 15) startupScore -= 25;
                else if (startupItems.Count > 10) startupScore -= 15;
                else if (startupItems.Count > 5) startupScore -= 5;
                startupScore = Math.Clamp(startupScore, 30, 100);
            }

            // Browser score calculation
            if (_browserScanner != null)
            {
                var profiles = await _browserScanner.ScanAllBrowsersAsync(cancellationToken);
                var allExt = profiles.SelectMany(p => p.Extensions).ToList();
                int suspExt = allExt.Count(e => e.RiskLevel >= RiskLevel.Suspicious);
                browserScore -= suspExt * 15;
                browserScore = Math.Clamp(browserScore, 20, 100);
            }

            int overall = (int)Math.Round(
                (securityScore * 0.35) +
                (perfScore * 0.20) +
                (stabilityScore * 0.20) +
                (startupScore * 0.15) +
                (browserScore * 0.10));

            return new HealthScore
            {
                OverallScore = overall,
                SecurityScore = securityScore,
                PerformanceScore = perfScore,
                StabilityScore = stabilityScore,
                StartupScore = startupScore,
                BrowserSecurityScore = browserScore,
                ActiveFindingsCount = activeFindings,
                RecentCrashCount = recentCrashes,
                LastCalculatedAt = DateTime.UtcNow
            };
        }
    }
}
