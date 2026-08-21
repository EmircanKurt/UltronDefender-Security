using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface ISecurityFindingService
{
    Task<List<SecurityFinding>> GetAllFindingsAsync(CancellationToken cancellationToken = default);
    Task<List<SecurityFinding>> GetFindingsByRiskAsync(RiskLevel riskLevel, CancellationToken cancellationToken = default);
    Task AddFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default);
    Task UpdateFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default);
    Task<SecurityFinding?> GetFindingByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<int> GetActiveCountAsync(CancellationToken cancellationToken = default);
}
