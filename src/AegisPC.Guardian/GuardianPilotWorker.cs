using AegisPC.Contracts.Protection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>Runs only a source pilot heartbeat. Critical listeners/vault ownership remain unverified, not independently protected.</summary>
internal sealed class GuardianPilotWorker(IGuardianHealthMonitor health, ILogger<GuardianPilotWorker> logger) : BackgroundService
{
    /// <summary>Reports the actual zero-observer/pending-ownership state without creating files, watchers or native actions.</summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogWarning("Guardian source pilot only. Native IPC, critical observers and exclusive vault migration are not enabled.");
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        do { health.ObserveHeartbeat(activeObservers: 0, vaultOwnershipVerified: false); }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
