using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Infrastructure;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Infrastructure.Database;
using AegisPC.Infrastructure.Database.Repositories;
using AegisPC.Infrastructure.Elevation;
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

namespace AegisPC.Service
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
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

                    // Hosted Background Workers
                    services.AddHostedService<ProtectionWorker>();
                    services.AddHostedService<NamedPipeServer>();
                    services.AddHostedService<ScanScheduler>();
                })
                .ConfigureLogging((hostContext, logging) =>
                {
                    logging.ClearProviders();
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
    }
}
