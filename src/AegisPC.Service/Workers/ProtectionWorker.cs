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
        private readonly IEtwPreExecProtectionService? _etwPreExecService;
        private readonly AegisPC.Service.DriverBridge.IKernelBridge? _kernelBridge;
        private readonly AegisPC.Service.RealTime.EtwProcessMonitor? _processMonitor;
        private readonly AegisPC.Service.RealTime.EtwImageLoadMonitor? _imageLoadMonitor;
        private readonly AegisPC.Service.Network.INetworkProtectionService? _networkProtectionService;

        public ProtectionWorker(
            ILogger<ProtectionWorker> logger,
            IBackgroundProtectionService fileProtectionService,
            IRealTimeProtectionEngine realTimeProtectionEngine,
            IRansomwareProtectionEngine ransomwareEngine,
            IBehaviorEngine behaviorEngine,
            SettingsService settingsService,
            IEtwPreExecProtectionService? etwPreExecService = null,
            AegisPC.Service.DriverBridge.IKernelBridge? kernelBridge = null,
            AegisPC.Service.RealTime.EtwProcessMonitor? processMonitor = null,
            AegisPC.Service.RealTime.EtwImageLoadMonitor? imageLoadMonitor = null,
            AegisPC.Service.Network.INetworkProtectionService? networkProtectionService = null)
        {
            _logger = logger;
            _fileProtectionService = fileProtectionService;
            _realTimeProtectionEngine = realTimeProtectionEngine;
            _ransomwareEngine = ransomwareEngine;
            _behaviorEngine = behaviorEngine;
            _settingsService = settingsService;
            _etwPreExecService = etwPreExecService;
            _kernelBridge = kernelBridge;
            _processMonitor = processMonitor;
            _imageLoadMonitor = imageLoadMonitor;
            _networkProtectionService = networkProtectionService;
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

                    try
                    {
                        _logger.LogInformation("Starting ETW Pre-Execution Protection Layer...");
                        _etwPreExecService?.Start();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to start ETW Pre-Execution Protection Service.");
                    }

                    try
                    {
                        _logger.LogInformation("Starting ETW Process & Image Telemetry Monitors...");
                        _processMonitor?.Start();
                        _imageLoadMonitor?.Start();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to start ETW Process/Image Monitors.");
                    }

                    try
                    {
                        _logger.LogInformation("Starting Kernel Minifilter Driver Bridge...");
                        _kernelBridge?.StartBridge();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to connect Kernel Driver Bridge (continuing in user-mode).");
                    }

                    try
                    {
                        _logger.LogInformation("Starting Network & DNS Protection Service...");
                        _networkProtectionService?.Start();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to start Network Protection Service.");
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
                    _logger.LogDebug("ProtectionWorker heartbeat: FileProtection={FileActive}, RansomwareShield={RansomwareActive}, KernelBridge={KernelActive}, NetworkProtection={NetworkActive}",
                        _fileProtectionService.IsProtectionActive, _ransomwareEngine.IsShieldActive, _kernelBridge?.IsDriverConnected ?? false, _networkProtectionService?.IsRunning ?? false);
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
                try { _networkProtectionService?.Stop(); } catch { }
                try { _etwPreExecService?.Stop(); } catch { }
                try { _processMonitor?.Stop(); } catch { }
                try { _imageLoadMonitor?.Stop(); } catch { }
                try { _kernelBridge?.StopBridge(); } catch { }
            }
        }
    }
}
