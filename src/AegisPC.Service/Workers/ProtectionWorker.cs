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
                    _logger.LogInformation("Starting Real-Time Progressive Protection Engine...");
                    _realTimeProtectionEngine.Start();
                    _fileProtectionService.StartProtection();
                }

                if (_settingsService.Current.IsRansomwareShieldEnabled)
                {
                    _logger.LogInformation("Starting Ransomware Canary Shield subsystem...");
                    _ransomwareEngine.StartShield();
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
                _fileProtectionService.StopProtection();
                _ransomwareEngine.StopShield();
            }
        }
    }
}
