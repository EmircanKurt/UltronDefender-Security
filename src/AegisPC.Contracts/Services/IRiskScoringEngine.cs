using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IRiskScoringEngine
{
    Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(FileAnalysisResult result, CancellationToken cancellationToken = default);
}
