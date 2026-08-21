using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Infrastructure.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Scheduler
{
    public class ScanScheduler : BackgroundService
    {
        private readonly ILogger<ScanScheduler> _logger;
        private readonly IScanCoordinatorService _scanCoordinator;
        private readonly SettingsService _settingsService;

        private DateTime? _lastRunDate;

        public ScanScheduler(
            ILogger<ScanScheduler> logger,
            IScanCoordinatorService scanCoordinator,
            SettingsService settingsService)
        {
            _logger = logger;
            _scanCoordinator = scanCoordinator;
            _settingsService = settingsService;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("ScanScheduler background worker started.");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // Check every minute
                    await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);

                    var settings = _settingsService.Current;
                    if (!settings.ScanScheduleEnabled)
                    {
                        continue;
                    }

                    var now = DateTime.Now;
                    if (ScanScheduleEvaluator.IsDailyScanDue(now, settings.ScheduledScanHour, _lastRunDate))
                    {
                        _logger.LogInformation("Triggering scheduled routine quick scan at hour {Hour}...", now.Hour);
                        _lastRunDate = now.Date;

                        try
                        {
                            var result = await _scanCoordinator.StartScanAsync(ScanType.Quick);
                            if (result != null)
                            {
                                _logger.LogInformation("Scheduled scan completed. Files: {Files}, Threats: {Threats}",
                                    result.ScannedFiles, result.Findings.Count);
                            }
                        }
                        catch (Exception scanEx) when (scanEx is not OperationCanceledException)
                        {
                            _logger.LogError(scanEx, "Scheduled scan failed with error.");
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error in ScanScheduler loop.");
                }
            }

            _logger.LogInformation("ScanScheduler background worker stopped.");
        }
    }
}
