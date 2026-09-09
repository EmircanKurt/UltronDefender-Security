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
                        services.AddSingleton<SettingsService>();
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
                        services.AddSingleton<ISignatureVerifier, SignatureVerifier>();
                        services.AddSingleton<IRiskScoringEngine, RiskScoringEngine>();
                        services.AddSingleton<IAllowlistService, AllowlistService>();
                        services.AddSingleton<IQuarantineService, QuarantineService>();
                        services.AddSingleton<ISecurityFindingService, SecurityFindingService>();
                        services.AddSingleton<IScanResourceManager, AdaptiveScanResourceManager>();
                        services.AddSingleton<IScanSessionManager, ScanSessionManager>();
                        services.AddSingleton<IFileScanner, FileScannerService>();
                        services.AddSingleton<IScanCoordinatorService, ScanCoordinatorService>();
                        services.AddSingleton<IReputationService, ReputationService>();
                        services.AddSingleton<ArchiveSafetyScanner>();

                        // Real-Time Security Engines
                        services.AddSingleton<IBehaviorEngine, BehaviorEngine>();
                        services.AddSingleton<IRealTimeProtectionEngine, RealTimeProtectionEngine>();
                        services.AddSingleton<IBackgroundProtectionService, BackgroundProtectionService>();
                        services.AddSingleton<IRansomwareProtectionEngine, RansomwareProtectionEngine>();
                        services.AddSingleton<IWebShieldService, WebShieldService>();
                        services.AddSingleton<AegisPC.Security.Detection.YaraEngine.IYaraEngine, AegisPC.Security.Detection.YaraEngine.YaraEngine>();
                        services.AddSingleton<AegisPC.Contracts.Detection.IDetectionHub>(sp => AegisPC.Security.Detection.DetectionHubFactory.CreateDefault(
                            sp.GetRequiredService<IHashService>(),
                            sp.GetRequiredService<ISignatureVerifier>(),
                            yaraEngine: sp.GetRequiredService<AegisPC.Security.Detection.YaraEngine.IYaraEngine>(),
                            reputationService: sp.GetService<IReputationService>()));
                        services.AddSingleton<IEtwPreExecProtectionService, EtwPreExecProtectionService>();
                        services.AddSingleton<AegisPC.Service.DriverBridge.IKernelBridge, AegisPC.Service.DriverBridge.KernelBridge>();
                        services.AddSingleton<AegisPC.Service.RealTime.EtwProcessMonitor>();
                        services.AddSingleton<AegisPC.Service.RealTime.EtwImageLoadMonitor>();

                        // Network & Offline DNS Protection
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
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }
    }
}
