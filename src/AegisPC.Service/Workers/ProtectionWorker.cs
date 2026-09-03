using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.RealTime;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Workers
{
    public class ProtectionWorker : BackgroundService
    {
        private readonly ILogger<ProtectionWorker> _logger;
        private readonly IBackgroundProtectionService _fileProtectionService;
        private readonly IRealTimeProtectionEngine _realTimeProtectionEngine;
        private readonly IRansomwareProtectionEngine _ransomwareEngine;
        private readonly IBehaviorEngine _behaviorEngine;
        private readonly SettingsService _settingsService;

        public ProtectionWorker(
            ILogger<ProtectionWorker> logger,
            IBackgroundProtectionService fileProtectionService,
            IRealTimeProtectionEngine realTimeProtectionEngine,
            IRansomwareProtectionEngine ransomwareEngine,
            IBehaviorEngine behaviorEngine,
            SettingsService settingsService)
        {
            _logger = logger;
            _fileProtectionService = fileProtectionService;
            _realTimeProtectionEngine = realTimeProtectionEngine;
            _ransomwareEngine = ransomwareEngine;
            _behaviorEngine = behaviorEngine;
            _settingsService = settingsService;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("AegisPC Protection Service background worker initializing.");

            try
            {
                await _settingsService.LoadAsync(stoppingToken);

                if (_settingsService.Current.IsFileProtectionEnabled)
                {
                    try
                    {
                        _logger.LogInformation("Starting Real-Time Progressive Protection Engine...");
                        _realTimeProtectionEngine.Start();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to start Real-Time Protection Engine.");
                    }

                    try
                    {
                        _logger.LogInformation("Starting File Protection Service...");
                        _fileProtectionService.StartProtection();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to start File Protection Service.");
                    }
                }

                if (_settingsService.Current.IsRansomwareShieldEnabled)
                {
                    try
                    {
                        _logger.LogInformation("Starting Ransomware Canary Shield subsystem...");
                        _ransomwareEngine.StartShield();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to start Ransomware Shield.");
                    }
                }

                _logger.LogInformation("AegisPC Protection Service is active and monitoring.");

                // Heartbeat / health check loop
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
                    _logger.LogDebug("ProtectionWorker heartbeat: FileProtection={FileActive}, RansomwareShield={RansomwareActive}",
                        _fileProtectionService.IsProtectionActive, _ransomwareEngine.IsShieldActive);
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception in ProtectionWorker.");
            }
            finally
            {
                _logger.LogInformation("Stopping protection engines during service shutdown.");
                try { _realTimeProtectionEngine?.Stop(); } catch { }
                try { _fileProtectionService?.StopProtection(); } catch { }
                try { _ransomwareEngine?.StopShield(); } catch { }
            }
        }
    }
}
