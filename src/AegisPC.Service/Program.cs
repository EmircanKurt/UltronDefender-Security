using System;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Infrastructure;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Infrastructure.Database;
using AegisPC.Infrastructure.Database.Repositories;
using AegisPC.Infrastructure.Elevation;
using AegisPC.Infrastructure.Logging;
using AegisPC.Infrastructure.SecureStorage;
using AegisPC.Security.RealTime;
using AegisPC.Security.Reputation;
using AegisPC.Security.Scanning;
using AegisPC.Service.IPC;
using AegisPC.Service.Scheduler;
using AegisPC.Service.Workers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

namespace AegisPC.Service
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            // Serilog Rolling File Yapılandırması (10MB limit, günlük rotation, hassas veri filtreleme)
            Log.Logger = SerilogConfiguration.Configure();

            // Servis Çökme Koruması (Unhandled Exception Hook'ları)
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                var ex = e.ExceptionObject as Exception;
                Log.Fatal(ex, "AegisPC Service sonlandırıcı hata: AppDomain UnhandledException.");
                Log.CloseAndFlush();
            };

            TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                Log.Error(e.Exception, "AegisPC Service arka plan Task'ında yakalanmamış istisna.");
                e.SetObserved();
            };

            try
            {
                Log.Information("AegisPC Protection Service başlatılıyor...");

                var host = Host.CreateDefaultBuilder(args)
                    .UseWindowsService(options =>
                    {
                        options.ServiceName = "AegisPC Protection Service";
                    })
                    .ConfigureServices((hostContext, services) =>
                    {
                        // Infrastructure
                        services.AddSingleton<DatabaseService>();
                        services.AddSingleton<IDatabaseService>(sp => sp.GetRequiredService<DatabaseService>());
                        // Windows Service, kullanıcı profilinden bağımsız tek bir makine ayarı kullanır.
                        // SYSTEM hesabının Roaming AppData'sı UI kullanıcısının ayarlarıyla karışmamalıdır.
                        services.AddSingleton(_ => new SettingsService(System.IO.Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                            "AegisPC", "settings.json")));
                        services.AddSingleton<ISettingsService>(sp => sp.GetRequiredService<SettingsService>());
                        services.AddSingleton<ISecureStorageService, DpapiSecureStorageService>();
                        services.AddSingleton<IAuditLogService, AuditLogService>();
                        services.AddSingleton<IElevationService, ElevationService>();

                        // Repositories
                        services.AddSingleton<AuditLogRepository>();
                        services.AddSingleton<PerformanceSampleRepository>();
                        services.AddSingleton<FileHashRepository>();
                        services.AddSingleton<SecurityFindingRepository>();
                        services.AddSingleton<ScanHistoryRepository>();
                        services.AddSingleton<CrashEventRepository>();
                        services.AddSingleton<WindowsEventRepository>();
                        services.AddSingleton<QuarantineRepository>();

                        // Security & Scanning
                        services.AddSingleton<IHashService, HashService>();
                        services.AddSingleton<IFileContentClassifier, FileContentClassifier>();
                        services.AddSingleton<IScanTargetResolver, WindowsScanTargetResolver>();
                        services.AddSingleton<IScanVolumeTargetResolver, WindowsScanVolumeTargetResolver>();
                        services.AddSingleton<ISignatureVerifier, SignatureVerifier>();
                        services.AddSingleton<IRiskScoringEngine, RiskScoringEngine>();
                        services.AddSingleton<IExclusionService, AegisPC.Security.Safety.ExclusionService>();
                        services.AddSingleton<IAllowlistService, AllowlistService>();
                        services.AddSingleton<IFileHashMatcher, FileHashMatcher>();
                        services.AddSingleton<AegisPC.Contracts.Safety.IProtectedPathGuard, AegisPC.Security.Safety.ProtectedPathGuard>();
                        services.AddSingleton<AegisPC.Contracts.Safety.IReparsePointGuard, AegisPC.Security.Safety.ReparsePointGuard>();
                        services.AddSingleton<IQuarantineService, QuarantineService>();
                        services.AddSingleton<ISecurityFindingService, SecurityFindingService>();
                        services.AddSingleton<IScanResourceManager, AdaptiveScanResourceManager>();
                        services.AddSingleton<IScanSessionManager, ScanSessionManager>();
                        services.AddSingleton<IFileScanner>(sp => new FileScannerService(
                            new DirectoryWalker(sp.GetRequiredService<IScanTargetResolver>(), sp.GetRequiredService<IScanVolumeTargetResolver>()), new ScanQueueCoordinator(sp.GetRequiredService<IScanResourceManager>()),
                            sp.GetRequiredService<IFileHashMatcher>(),
                            new PupAnalysisCoordinator(sp.GetRequiredService<AegisPC.Contracts.Detection.IDetectionHub>(), sp.GetRequiredService<ISecurityFindingService>()),
                            sp.GetRequiredService<ArchiveSafetyScanner>(), sp.GetRequiredService<ISecurityFindingService>(),
                            sp.GetService<ILogger<FileScannerService>>(), sp.GetRequiredService<IFileContentClassifier>()));
                        services.AddSingleton<ScanCoordinatorService>();
                        services.AddSingleton<IScanCoordinatorService>(sp => sp.GetRequiredService<ScanCoordinatorService>());
                        services.AddSingleton<IBackgroundScanCoordinator>(sp => sp.GetRequiredService<ScanCoordinatorService>());
                        services.AddSingleton<AegisPC.Contracts.Policy.IPolicyEngine, AegisPC.Security.Policy.PolicyEngine>();
                        services.AddSingleton<IReputationService, ReputationService>();
                        services.AddSingleton<ArchiveSafetyScanner>();

                        // Real-Time Security Engines
                        services.AddSingleton<IBehaviorEngine, BehaviorEngine>();
                        services.AddSingleton<RansomwareShieldActivation>();
                        services.AddSingleton<IRealTimeProtectionEngine>(sp => new RealTimeProtectionEngine(
                            sp.GetRequiredService<IFileScanner>(), sp.GetRequiredService<IHashService>(), sp.GetRequiredService<ISignatureVerifier>(), sp.GetRequiredService<IRiskScoringEngine>(),
                            sp.GetRequiredService<IQuarantineService>(), sp.GetRequiredService<ISecurityFindingService>(),
                            sp.GetService<IAuditLogService>(), sp.GetService<IReputationService>(), sp.GetService<ILogger<RealTimeProtectionEngine>>(), sp.GetRequiredService<IExclusionService>(),
                            () => sp.GetRequiredService<ISettingsService>().GetSetting("EnableAutoQuarantine", true),
                            () => sp.GetRequiredService<ISettingsService>().GetSetting("AutoQuarantineThreshold", 85),
                            detectionHub: sp.GetRequiredService<AegisPC.Contracts.Detection.IDetectionHub>(),
                            backgroundResources: sp.GetRequiredService<IScanResourceManager>(),
                            scanTargets: sp.GetRequiredService<IScanTargetResolver>()));
                        services.AddSingleton<AegisPC.Contracts.Devices.IDeviceStorageResolver, AegisPC.Service.Devices.WindowsDeviceStorageResolver>();
                        services.AddSingleton<AegisPC.Contracts.Devices.IDeviceInventorySource, AegisPC.Service.Devices.WindowsDeviceInventorySource>();
                        services.AddSingleton<AegisPC.Service.Devices.MediaProtectionCoordinator>();
                        services.AddSingleton<AegisPC.Contracts.Devices.IDeviceInventoryMonitor>(sp =>
                        {
                            var media = sp.GetRequiredService<AegisPC.Service.Devices.MediaProtectionCoordinator>();
                            return new AegisPC.Service.Devices.DeviceInventoryMonitor(
                                sp.GetRequiredService<AegisPC.Contracts.Devices.IDeviceInventorySource>(),
                                media.InspectAsync, media.RemoveAsync,
                                sp.GetService<ILogger<AegisPC.Service.Devices.DeviceInventoryMonitor>>());
                        });
                        services.AddSingleton<IBackgroundProtectionService, BackgroundProtectionService>();
                        services.AddSingleton<IRansomwareProtectionEngine, RansomwareProtectionEngine>();
                        services.AddSingleton<IWebShieldService, WebShieldService>();
                        services.AddSingleton<IAmsiScanService, AegisPC.Security.Scanning.AmsiScanService>();
                        services.AddSingleton<AegisPC.Security.Detection.YaraEngine.IYaraEngine, AegisPC.Security.Detection.YaraEngine.YaraEngine>();
                        services.AddSingleton<AegisPC.Contracts.Detection.IDetectionHub>(sp => AegisPC.Security.Detection.DetectionHubFactory.CreateDefault(
                            sp.GetRequiredService<IHashService>(),
                            sp.GetRequiredService<ISignatureVerifier>(),
                            yaraEngine: sp.GetRequiredService<AegisPC.Security.Detection.YaraEngine.IYaraEngine>(),
                            reputationService: sp.GetService<IReputationService>(),
                            exclusionService: sp.GetRequiredService<IExclusionService>(),
                            amsiScanService: sp.GetRequiredService<IAmsiScanService>(),
                            isUltronAiEnabled: () => sp.GetRequiredService<ISettingsService>().GetSetting("IsUltronAiEnabled", true)));
                        services.AddSingleton<IEtwPreExecProtectionService>(sp => new EtwPreExecProtectionService(
                            sp.GetRequiredService<AegisPC.Contracts.Detection.IDetectionHub>(), sp.GetRequiredService<IRiskScoringEngine>(), sp.GetRequiredService<ISignatureVerifier>(),
                            quarantineService: sp.GetRequiredService<IQuarantineService>(), auditLogService: sp.GetService<IAuditLogService>(),
                            logger: sp.GetService<ILogger<EtwPreExecProtectionService>>(), exclusionService: sp.GetRequiredService<IExclusionService>(),
                            enableAutoQuarantine: () => sp.GetRequiredService<ISettingsService>().GetSetting("EnableAutoQuarantine", true),
                            autoQuarantineThreshold: () => sp.GetRequiredService<ISettingsService>().GetSetting("AutoQuarantineThreshold", 85)));
                        services.AddSingleton<AegisPC.Service.DriverBridge.IKernelBridge, AegisPC.Service.DriverBridge.KernelBridge>();
                        services.AddSingleton<AegisPC.Service.RealTime.EtwProcessMonitor>();
                        services.AddSingleton<AegisPC.Service.RealTime.EtwImageLoadMonitor>();
                        services.AddSingleton<AegisPC.Contracts.Protection.IUltronDecisionEngine, AegisPC.Security.UltronAI.UltronDecisionEngine>();
                        services.AddSingleton<AegisPC.Security.UltronAI.PilotGatedActionAdapter>();
                        services.AddSingleton<AegisPC.Contracts.Protection.IProtectionActionBroker>(sp =>
                            new AegisPC.Security.UltronAI.ProtectionActionBroker(
                                sp.GetRequiredService<AegisPC.Security.UltronAI.PilotGatedActionAdapter>(),
                                sp.GetRequiredService<AegisPC.Security.UltronAI.PilotGatedActionAdapter>()));
                        services.AddSingleton<AegisPC.Contracts.Protection.IBehaviorObservationSource, AegisPC.Security.UltronAI.BoundedBehaviorObservationSource>();
                        services.AddSingleton<AegisPC.Security.UltronAI.BehaviorWindowCorrelator>();
                        services.AddSingleton<AegisPC.Service.RealTime.EtwFileIoObservationWorker>();
                        services.AddHostedService(sp => sp.GetRequiredService<AegisPC.Service.RealTime.EtwFileIoObservationWorker>());
                        services.AddSingleton<UltronObservationWorker>();
                        services.AddHostedService(sp => sp.GetRequiredService<UltronObservationWorker>());

                        // Network & Offline DNS Protection
                        // Passive observations only. Native action pilots are intentionally not registered here.
                        services.AddSingleton<AegisPC.Contracts.Protection.IConsolePresenceObserver, AegisPC.Service.Remote.WindowsConsolePresenceObserver>();
                        services.AddSingleton<AegisPC.Contracts.Protection.IRdpLogonObservationSource, AegisPC.Service.Remote.WindowsRdpLogonObservationSource>();
                        services.AddSingleton<AegisPC.Service.Remote.RemoteProtectionPolicy>();
                        services.AddSingleton<AegisPC.Contracts.Protection.IRemoteProtectionMonitor, AegisPC.Service.Remote.RemoteProtectionMonitor>();
                        services.AddSingleton<AegisPC.Contracts.Protection.IWirelessInventoryObserver>(sp =>
                            new AegisPC.Service.Wireless.WindowsWirelessInventoryObserver(false,
                                sp.GetService<ILogger<AegisPC.Service.Wireless.WindowsWirelessInventoryObserver>>()));
                        services.AddSingleton<AegisPC.Service.Wireless.WirelessProtectionPolicy>();
                        services.AddSingleton<AegisPC.Contracts.Protection.IWirelessProtectionMonitor, AegisPC.Service.Wireless.WirelessProtectionMonitor>();
                        services.AddSingleton<PassiveSecurityObservationWorker>();
                        services.AddHostedService(sp => sp.GetRequiredService<PassiveSecurityObservationWorker>());
                        services.AddSingleton<AegisPC.Contracts.Network.INetworkProcessCorrelator, AegisPC.Security.Network.NetworkProcessCorrelator>();
                        services.AddSingleton<AegisPC.Service.Network.HostsInjectionHelper>();
                        services.AddSingleton<AegisPC.Service.Network.UrlBlocklistManager>();
                        services.AddSingleton<AegisPC.Service.Network.DnsFilterService>();
                        services.AddSingleton<AegisPC.Service.Network.ThreatFeedManager>();
                        services.AddSingleton<AegisPC.Service.Network.IWfpEnforcementService, AegisPC.Service.Network.WfpEnforcementService>();
                        services.AddSingleton<AegisPC.Service.Network.INetworkProtectionService, AegisPC.Service.Network.NetworkProtectionService>();
                        services.AddSingleton<AegisPC.Service.Network.NetworkProtectionService>(sp => (AegisPC.Service.Network.NetworkProtectionService)sp.GetRequiredService<AegisPC.Service.Network.INetworkProtectionService>());

                        // Update & Rollback Engine
                        services.AddSingleton<AegisPC.Service.Update.IAutoUpdateService, AegisPC.Service.Update.AutoUpdateService>();
                        services.AddSingleton<AegisPC.Service.Update.AutoUpdateService>(sp => (AegisPC.Service.Update.AutoUpdateService)sp.GetRequiredService<AegisPC.Service.Update.IAutoUpdateService>());

                        // SmartScreen & MOTW Download Guard
                        services.AddSingleton<AegisPC.Service.SmartScreen.ZoneIdentifierAnalyzer>();
                        services.AddSingleton<AegisPC.Service.SmartScreen.DownloadGuard>();

                        // Hosted Background Workers
                        services.AddSingleton<IScanSchedulerEnvironmentProvider, AegisPC.Infrastructure.Platform.WindowsScanSchedulerEnvironmentProvider>();
                        services.AddSingleton<IIdleTimeProvider, IdleDetector>();
                        services.AddSingleton<IScanScheduleStateStore, FileScanScheduleStateStore>();
                        services.AddHostedService<ProtectionWorker>();
                        services.AddHostedService<NamedPipeServer>();
                        services.AddHostedService<ScanScheduler>();
                    })
                    .ConfigureLogging((hostContext, logging) =>
                    {
                        logging.ClearProviders();
                        logging.AddSerilog(Log.Logger, dispose: true);
                        logging.AddConsole();
                        logging.AddEventLog(settings =>
                        {
                            settings.SourceName = "AegisPC Protection Service";
                        });
                    })
                    .Build();

                // Initialize database schema
                using (var scope = host.Services.CreateScope())
                {
                    var db = scope.ServiceProvider.GetRequiredService<DatabaseService>();
                    await db.InitializeAsync();
                }

                await host.RunAsync();
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "AegisPC Protection Service başlatılamadı.");
                Environment.ExitCode = 1;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }
    }
}
