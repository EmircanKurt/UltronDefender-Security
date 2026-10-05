using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Contracts.ThreatIntelligence;
using AegisPC.Core.Configuration;
using AegisPC.Core.Models;
using AegisPC.Security.ThreatIntelligence;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Reputation;

/// <summary>Local-only exact reputation. No files, hashes, API keys or observations leave the endpoint.</summary>
public sealed class ReputationService : IReputationService, IDisposable
{
    /// <summary>Compatibility preference: cloud queries are unavailable in this local-only edition.</summary>
    public bool IsCloudLookupEnabled { get => false; set => FeatureFlags.IsCloudLookupActive = false; }
    public int CacheCount => 0;
    public void ClearCache() { }

    /// <summary>Legacy injected HTTP client remains caller-owned and is never used or configured.</summary>
    public ReputationService(ISettingsService? settingsService = null,
        ILogger<ReputationService>? logger = null, HttpClient? httpClient = null)
    {
        FeatureFlags.IsCloudLookupActive = false;
    }

    /// <summary>Cancellation propagates. Invalid, absent, unsigned or expired evidence stays unknown.</summary>
    public Task<ReputationResult> CheckReputationAsync(string sha256, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Sha256Identity.IsValid(sha256) && AuthoritativeThreatCatalog.TryGet(sha256, out var record) && record != null)
            return Task.FromResult(new ReputationResult
            {
                IsKnown = true, IsMalicious = true, ThreatName = record.ThreatName, Severity = record.Severity,
                MalwareFamily = record.Category, Tags = new[] { record.Category }, DetectionCount = 1,
                TotalEngines = 1, Source = record.Source, CheckedAt = DateTime.UtcNow,
                Details = $"Doğrulanmış yerel kayıt: {record.ThreatName}; kaynak: {record.SourceReference}."
            });
        return Task.FromResult(new ReputationResult
        {
            IsKnown = false, IsMalicious = false, Source = "LocalOnly", CheckedAt = DateTime.UtcNow,
            Details = "Doğrulanmış yerel hash kaydı yok; sonuç bilinmiyor. Dosya veya hash buluta gönderilmedi."
        });
    }

    public void Dispose() { }
}

