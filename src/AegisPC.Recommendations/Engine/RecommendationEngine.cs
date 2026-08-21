using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Recommendations.Rules;
using Microsoft.Extensions.Logging;

namespace AegisPC.Recommendations.Engine
{
    public class RecommendationEngine : IRecommendationEngine
    {
        private readonly ISecurityFindingService? _findingService;
        private readonly IPerformanceMonitor? _performanceMonitor;
        private readonly ICrashAnalyzer? _crashAnalyzer;
        private readonly IStartupAnalyzer? _startupAnalyzer;
        private readonly IBrowserSecurityScanner? _browserScanner;
        private readonly ILogger<RecommendationEngine>? _logger;

        private readonly List<Recommendation> _cachedRecommendations = new();
        private readonly object _lock = new();

        public RecommendationEngine(
            ISecurityFindingService? findingService = null,
            IPerformanceMonitor? performanceMonitor = null,
            ICrashAnalyzer? crashAnalyzer = null,
            IStartupAnalyzer? startupAnalyzer = null,
            IBrowserSecurityScanner? browserScanner = null,
            ILogger<RecommendationEngine>? logger = null)
        {
            _findingService = findingService;
            _performanceMonitor = performanceMonitor;
            _crashAnalyzer = crashAnalyzer;
            _startupAnalyzer = startupAnalyzer;
            _browserScanner = browserScanner;
            _logger = logger;
        }

        public async Task<List<Recommendation>> GenerateRecommendationsAsync(CancellationToken cancellationToken = default)
        {
            var results = new List<Recommendation>();

            try
            {
                // 1. Security & Browser Rules
                var secRecs = await SecurityRule.EvaluateAsync(_findingService, _browserScanner, cancellationToken);
                results.AddRange(secRecs);

                // 2. Performance Rules
                var perfRecs = await PerformanceRule.EvaluateAsync(_performanceMonitor, cancellationToken);
                results.AddRange(perfRecs);

                // 3. Stability Rules
                var stabRecs = await StabilityRule.EvaluateAsync(_crashAnalyzer, cancellationToken);
                results.AddRange(stabRecs);

                // 4. Startup Rules
                if (_startupAnalyzer != null)
                {
                    var startupRecs = await _startupAnalyzer.AnalyzeStartupImpactAsync(cancellationToken);
                    results.AddRange(startupRecs);
                }

                lock (_lock)
                {
                    int idCounter = 1;
                    foreach (var rec in results)
                    {
                        rec.Id = idCounter++;
                        rec.Status = RecommendationStatus.Active;
                    }

                    _cachedRecommendations.Clear();
                    _cachedRecommendations.AddRange(results);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error generating recommendations.");
            }

            return results;
        }

        public Task<List<Recommendation>> GetActiveRecommendationsAsync(CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                return Task.FromResult(_cachedRecommendations.Where(r => r.Status == RecommendationStatus.Active).ToList());
            }
        }

        public Task<bool> ApplyRecommendationAsync(int id, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var rec = _cachedRecommendations.FirstOrDefault(r => r.Id == id);
                if (rec != null)
                {
                    rec.Status = RecommendationStatus.Applied;
                    rec.UpdatedAt = DateTime.UtcNow;
                    return Task.FromResult(true);
                }
            }
            return Task.FromResult(false);
        }

        public Task<bool> DismissRecommendationAsync(int id, bool forever = false, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var rec = _cachedRecommendations.FirstOrDefault(r => r.Id == id);
                if (rec != null)
                {
                    rec.Status = RecommendationStatus.Dismissed;
                    rec.DismissedForever = forever;
                    rec.UpdatedAt = DateTime.UtcNow;
                    return Task.FromResult(true);
                }
            }
            return Task.FromResult(false);
        }
    }
}
