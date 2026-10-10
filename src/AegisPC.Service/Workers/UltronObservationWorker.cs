using AegisPC.Contracts.Protection;
using AegisPC.Contracts.Services;
using AegisPC.Security.UltronAI;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Workers;

/// <summary>Local review-only AI event consumer. No quarantine/kill broker is connected to new behavior rules.</summary>
public sealed class UltronObservationWorker(IBehaviorObservationSource source, BehaviorWindowCorrelator correlator,
    ISettingsService settings, ILogger<UltronObservationWorker> logger) : BackgroundService
{
    /// <summary>Last local review only; it is never an intervention permit or an unfiltered IPC payload.</summary>
    public BehaviorWindowReview? LatestReview { get; private set; }
    /// <summary>Whether the consumer is running, not whether all producers or protection layers are healthy.</summary>
    public bool IsObservationActive { get; private set; }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        IsObservationActive = true;
        try
        {
            await foreach (var observation in source.ReadAllAsync(stoppingToken))
            {
                if (!settings.GetSetting("IsUltronAiEnabled", true)) { LatestReview = null; correlator.Clear(); continue; }
                LatestReview = correlator.Observe(observation);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex) { logger.LogWarning("AI observation consumer failed ({FailureType}); observation health is degraded.", ex.GetType().Name); }
        finally { IsObservationActive = false; }
    }
}
