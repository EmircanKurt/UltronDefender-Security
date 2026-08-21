using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    public class SecurityFindingService : ISecurityFindingService
    {
        private readonly ILogger<SecurityFindingService>? _logger;
        private readonly List<SecurityFinding> _findings = new();
        private readonly object _lock = new();

        public SecurityFindingService(ILogger<SecurityFindingService>? logger = null)
        {
            _logger = logger;
        }

        public Task<List<SecurityFinding>> GetAllFindingsAsync(CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                return Task.FromResult(_findings.ToList());
            }
        }

        public Task<List<SecurityFinding>> GetFindingsByRiskAsync(RiskLevel riskLevel, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                return Task.FromResult(_findings.Where(f => f.RiskLevel == riskLevel).ToList());
            }
        }

        public Task AddFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                if (finding.Id == Guid.Empty)
                {
                    finding.Id = Guid.NewGuid();
                }
                finding.CreatedAt = DateTime.UtcNow;
                finding.UpdatedAt = DateTime.UtcNow;
                _findings.Add(finding);
            }
            _logger?.LogInformation("Security finding registered: {Title} ({RiskLevel})", finding.Title, finding.RiskLevel);
            return Task.CompletedTask;
        }

        public Task UpdateFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var existing = _findings.FirstOrDefault(f => f.Id == finding.Id);
                if (existing != null)
                {
                    existing.Status = finding.Status;
                    existing.IsAllowlisted = finding.IsAllowlisted;
                    existing.UpdatedAt = DateTime.UtcNow;
                }
            }
            return Task.CompletedTask;
        }

        public Task<SecurityFinding?> GetFindingByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var finding = _findings.FirstOrDefault(f => f.Id == id);
                return Task.FromResult(finding);
            }
        }

        public Task<int> GetActiveCountAsync(CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                return Task.FromResult(_findings.Count(f => f.Status == FindingStatus.Active));
            }
        }
    }
}
