using AegisPC.Contracts.Protection;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Workers;

/// <summary>Service-owned read-only observation lifecycle; no network, radio, recovery or driver action is executed.</summary>
public sealed class PassiveSecurityObservationWorker(IRdpLogonObservationSource logons,
    IRemoteProtectionMonitor remote, IWirelessProtectionMonitor wireless, ISettingsService settings,
    ILogger<PassiveSecurityObservationWorker> logger) : BackgroundService
{
    private int _running;
    private bool _subscribed;
    private DateTime _retrySubscriptionAfterUtc;
    /// <summary>True only while the service's capture loop is running, not proof that every native source is available.</summary>
    public bool IsObservationLoopRunning => Volatile.Read(ref _running) != 0;

    /// <summary>Starts bounded read-only adapters after host startup; constructors and tests remain inert.</summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            Volatile.Write(ref _running, 1);
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
            do
            {
                CaptureRemote(DateTime.UtcNow);
                try
                {
                    if (settings.GetSetting("EnableWirelessObservation", true)) wireless.Refresh(DateTime.UtcNow);
                }
                catch (Exception ex) { logger.LogWarning(ex, "Passive wireless capture failed; snapshot freshness must be checked"); }
            } while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            Volatile.Write(ref _running, 0);
            StopSubscription();
        }
    }

    private void CaptureRemote(DateTime utcNow)
    {
        try
        {
            if (!settings.GetSetting("EnableRemoteObservation", true))
            { StopSubscription(); _retrySubscriptionAfterUtc = default; return; }
            if (!_subscribed && utcNow >= _retrySubscriptionAfterUtc)
            {
                _retrySubscriptionAfterUtc = utcNow.AddSeconds(30);
                // Mark the attempted subscription before Start so a partially failed adapter is cleaned up.
                _subscribed = true;
                logons.Start();
            }
            var snapshot = remote.Refresh(utcNow);
            if (_subscribed && snapshot.LogonAvailability == SecurityObservationAvailability.Unavailable)
            {
                StopSubscription();
                _retrySubscriptionAfterUtc = utcNow.AddSeconds(30);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Passive remote capture failed; snapshot freshness must be checked");
            StopSubscription();
            _retrySubscriptionAfterUtc = utcNow.AddSeconds(30);
        }
    }

    private void StopSubscription()
    {
        if (!_subscribed) return;
        try { logons.Stop(); _subscribed = false; }
        catch (Exception ex) { logger.LogWarning(ex, "Passive remote subscription cleanup failed; retry remains bounded by the capture loop"); }
    }
}
