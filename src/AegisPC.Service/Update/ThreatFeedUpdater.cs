using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Security.Detection.YaraEngine;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Update;

/// <summary>Endpoint compatibility adapter. MalwareBazaar collection belongs to the developer tool, not this service.</summary>
public sealed class ThreatFeedUpdater
{
    public const string MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/";
    private readonly ILogger<ThreatFeedUpdater>? _logger;
    private readonly IYaraEngine? _yaraEngine;

    public ThreatFeedUpdater(HttpClient? httpClient = null, ISettingsService? settingsService = null,
        ILogger<ThreatFeedUpdater>? logger = null, IYaraEngine? yaraEngine = null)
    { _logger = logger; _yaraEngine = yaraEngine; }

    /// <summary>Reloads existing local YARA rules only; collecting hashes does not create YARA rules.</summary>
    public void ReloadYaraRules() => _yaraEngine?.ReloadRules();

    /// <summary>
    /// Compatibility method: never reads API credentials, queries the network, or marks a feed interval complete.
    /// Force/bootstrap cannot override the local-only boundary. Cancellation propagates.
    /// </summary>
    public Task<int> UpdateFromMalwareBazaarAsync(bool force = false, bool? forceBootstrap = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _logger?.LogInformation("Direct endpoint feed collection is disabled; use reviewed signed local intelligence packages.");
        return Task.FromResult(0);
    }
}
