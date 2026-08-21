using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IStartupAnalyzer
{
    Task<List<StartupItem>> GetStartupItemsAsync(CancellationToken cancellationToken = default);
    Task<List<Recommendation>> AnalyzeStartupImpactAsync(CancellationToken cancellationToken = default);
}
