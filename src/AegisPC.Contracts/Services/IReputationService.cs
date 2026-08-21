using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IReputationService
{
    Task<ReputationResult> CheckReputationAsync(string sha256, CancellationToken cancellationToken);
}
