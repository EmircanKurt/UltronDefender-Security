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
        private bool _lastEtwCoverageDegraded;
        private readonly AegisPC.Contracts.Devices.IDeviceInventoryMonitor? _devices;
        private readonly IScanTargetResolver? _scanTargets;
        private readonly RansomwareShieldActivation? _shieldActivation;

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
            AegisPC.Service.Network.INetworkProtectionService? networkProtectionService = null,
            AegisPC.Contracts.Devices.IDeviceInventoryMonitor? devices = null,
            IScanTargetResolver? scanTargets = null,
            RansomwareShieldActivation? shieldActivation = null)
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
            _devices = devices;
            _scanTargets = scanTargets;
            _shieldActivation = shieldActivation;
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
                        if (_settingsService.GetSetting("EnableExperimentalKernelBridge", false))
                        {
                            _logger.LogInformation("Connecting explicitly enabled experimental kernel bridge.");
                            _kernelBridge?.StartBridge();
                        }
                        else _logger.LogInformation("Experimental kernel bridging is disabled; supplemental user-mode protection remains selected.");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to connect Kernel Driver Bridge (continuing in user-mode).");
                    }

                }

                if (_settingsService.Current.IsNetworkProtectionEnabled)
                {
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
                        if (_shieldActivation != null) await _shieldActivation.StartAsync(stoppingToken).ConfigureAwait(false);
                        else
                        {
                            if (_scanTargets != null)
                                await new RansomwareShieldActivation(_ransomwareEngine, _scanTargets).StartAsync(stoppingToken).ConfigureAwait(false);
                            else _ransomwareEngine.StartShield();
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to start Ransomware Shield.");
                    }
                }

                if (_devices != null)
                {
                    try { await _devices.StartAsync(stoppingToken).ConfigureAwait(false); }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    { _logger.LogWarning(ex, "Device inventory is unavailable; no firmware or pre-input protection is claimed."); }
                }
                _logger.LogInformation("Protection service initialization finished; observed health is reported separately.");

                // Heartbeat / health check loop
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
                    int processEventsLost = _processMonitor?.EventsLost ?? -1;
                    int imageEventsLost = _imageLoadMonitor?.EventsLost ?? -1;
                    bool processEtwActive = _processMonitor?.IsRunning ?? false;
                    bool imageEtwActive = _imageLoadMonitor?.IsRunning ?? false;
                    bool etwCoverageDegraded = _settingsService.Current.IsFileProtectionEnabled &&
                        (!processEtwActive || !imageEtwActive || processEventsLost != 0 || imageEventsLost != 0);

                    _logger.LogDebug("ProtectionWorker heartbeat: FileProtection={FileActive}, RansomwareShield={RansomwareActive}, KernelBridge={KernelActive}, NetworkProtection={NetworkActive}, ProcessEtw={ProcessEtwActive}, ImageEtw={ImageEtwActive}, ProcessEventsLost={ProcessEventsLost}, ImageEventsLost={ImageEventsLost}",
                        _fileProtectionService.IsProtectionActive, _ransomwareEngine.IsShieldActive, _kernelBridge?.IsDriverConnected ?? false,
                        _networkProtectionService?.IsRunning ?? false, processEtwActive, imageEtwActive, processEventsLost, imageEventsLost);

                    if (etwCoverageDegraded != _lastEtwCoverageDegraded)
                    {
                        if (etwCoverageDegraded)
                            _logger.LogWarning("Optional ETW process/module telemetry is degraded: ProcessActive={ProcessActive}, ImageActive={ImageActive}, ProcessEventsLost={ProcessEventsLost}, ImageEventsLost={ImageEventsLost}. This is not pre-access blocking.",
                                processEtwActive, imageEtwActive, processEventsLost, imageEventsLost);
                        else
                            _logger.LogInformation("Optional ETW process/module telemetry is active with no reported event loss.");
                        _lastEtwCoverageDegraded = etwCoverageDegraded;
                    }
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
                try { if (_devices != null) await _devices.StopAsync(CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) { _logger.LogWarning(ex, "Error stopping device inventory"); }
                try { _realTimeProtectionEngine?.Stop(); } catch (Exception ex) { _logger.LogWarning(ex, "Error stopping RealTimeProtectionEngine"); }
                try { _fileProtectionService?.StopProtection(); } catch (Exception ex) { _logger.LogWarning(ex, "Error stopping FileProtectionService"); }
                try { _ransomwareEngine?.StopShield(); } catch (Exception ex) { _logger.LogWarning(ex, "Error stopping RansomwareEngine"); }
                try { _networkProtectionService?.Stop(); } catch (Exception ex) { _logger.LogWarning(ex, "Error stopping NetworkProtectionService"); }
                try { _etwPreExecService?.Stop(); } catch (Exception ex) { _logger.LogWarning(ex, "Error stopping EtwPreExecService"); }
                try { _processMonitor?.Stop(); } catch (Exception ex) { _logger.LogWarning(ex, "Error stopping ProcessMonitor"); }
                try { _imageLoadMonitor?.Stop(); } catch (Exception ex) { _logger.LogWarning(ex, "Error stopping ImageLoadMonitor"); }
                try { _kernelBridge?.StopBridge(); } catch (Exception ex) { _logger.LogWarning(ex, "Error stopping KernelBridge"); }
            }
        }
    }
}
