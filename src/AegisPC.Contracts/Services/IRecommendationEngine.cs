using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IRecommendationEngine
{
    Task<List<Recommendation>> GenerateRecommendationsAsync(CancellationToken cancellationToken = default);
    Task<List<Recommendation>> GetActiveRecommendationsAsync(CancellationToken cancellationToken = default);
    Task<bool> ApplyRecommendationAsync(int id, CancellationToken cancellationToken = default);
    Task<bool> DismissRecommendationAsync(int id, bool forever = false, CancellationToken cancellationToken = default);
}
