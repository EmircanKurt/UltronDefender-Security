using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services
{
    public class WebReputationVerdict
    {
        public string Url { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
        public bool IsBlocked { get; set; }
        public bool IsPhishing { get; set; }
        public bool IsDangerousDownload { get; set; }
        public int RiskScore { get; set; }
        public List<string> DetectionReasons { get; set; } = new();
        public string Recommendation { get; set; } = string.Empty;
        public DateTime CheckedAt { get; set; } = DateTime.UtcNow;
    }

    public interface IWebShieldService
    {
        Task<WebReputationVerdict> AnalyzeUrlAsync(string url, CancellationToken cancellationToken = default);
        bool AddBypassDomain(string domain);
        bool RemoveBypassDomain(string domain);
        IReadOnlyList<string> GetBypassDomains();
        bool AddBlockedDomain(string domain, string reason);
        IReadOnlyList<string> GetBlockedDomains();
    }
}
