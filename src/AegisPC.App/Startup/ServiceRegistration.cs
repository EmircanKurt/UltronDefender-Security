using AegisPC.App.Services;
using AegisPC.App.ViewModels;
using AegisPC.App.Views;
using AegisPC.BrowserSecurity.Browser;
using AegisPC.Contracts.Services;
using AegisPC.Diagnostics.Correlation;
using AegisPC.Diagnostics.Crash;
using AegisPC.Diagnostics.EventLog;
using AegisPC.Infrastructure;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Infrastructure.Database;
using AegisPC.Infrastructure.Database.Repositories;
using AegisPC.Infrastructure.Elevation;
using AegisPC.Infrastructure.SecureStorage;
using AegisPC.Performance.Monitoring;
using AegisPC.Performance.Network;
using AegisPC.Performance.Process;
using AegisPC.Persistence.Startup;
using AegisPC.Recommendations.AiExplanation;
using AegisPC.Recommendations.Engine;
using AegisPC.Security.Reputation;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AegisPC.App.Startup
{
    public static class ServiceRegistration
    {
        public static void RegisterServices(IServiceCollection services)
        {
            // Core Logging Infrastructure
            services.AddLogging();

            // Windows
            services.AddSingleton<MainWindow>();

            // Infrastructure Services
            services.AddSingleton<DatabaseService>();
            services.AddSingleton<IDatabaseService>(sp => sp.GetRequiredService<DatabaseService>());
            services.AddSingleton<SettingsService>();
            services.AddSingleton<ISettingsService>(sp => sp.GetRequiredService<SettingsService>());
            services.AddSingleton<ISecureStorageService, DpapiSecureStorageService>();
            services.AddSingleton<IAuditLogService, AuditLogService>();
            services.AddSingleton<IElevationService, ElevationService>();
            services.AddSingleton<INotificationService, NotificationService>();
            services.AddSingleton<IWindowsSecurityRegistrationService, WindowsSecurityRegistrationService>();

            // Repositories
            services.AddSingleton<AuditLogRepository>();
            services.AddSingleton<PerformanceSampleRepository>();
            services.AddSingleton<FileHashRepository>();
            services.AddSingleton<SecurityFindingRepository>();
            services.AddSingleton<ScanHistoryRepository>();
            services.AddSingleton<CrashEventRepository>();
            services.AddSingleton<WindowsEventRepository>();
            services.AddSingleton<RecommendationRepository>();
            services.AddSingleton<QuarantineRepository>();
            services.AddSingleton<StartupItemRepository>();
            services.AddSingleton<ApplicationInventoryRepository>();

            // Security & Scanning Services
            services.AddSingleton<IHashService, HashService>();
            services.AddSingleton<ISignatureVerifier, SignatureVerifier>();
            services.AddSingleton<IRiskScoringEngine, RiskScoringEngine>();

            // Behavior & Lineage Services (P0 Foundation)
            services.AddSingleton<AegisPC.Contracts.Behavior.IProcessLineageTracker, AegisPC.Security.Behavior.ProcessLineageTracker>();
            services.AddSingleton<AegisPC.Contracts.Behavior.IAttackChainCorrelator, AegisPC.Security.Behavior.AttackChainCorrelator>();
            services.AddSingleton<AegisPC.Contracts.Behavior.IProcessInjectionDetector, AegisPC.Security.Behavior.ProcessInjectionDetector>();

            // DetectionHub & Modular Detector Plugins (Phase 1-2)
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.HashSignatureDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.PeStaticDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.PE.DeepPeDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.EntropyDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.LocationReputationDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.ScriptHeuristicDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.AuthenticodeDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.PersistenceDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Archive.ArchiveDetectorPlugin>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.AntiEvasion.AntiEvasionDetectorPlugin>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.ProcessBehaviorDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.MemoryBehaviorDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.NetworkBehaviorDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectionHub, AegisPC.Security.Detection.DetectionHub>();
            services.AddSingleton<AegisPC.Core.Localization.ILocalizationService>(AegisPC.Core.Localization.LocalizationService.Instance);
            services.AddSingleton<IAllowlistService, AllowlistService>();
            services.AddSingleton<IQuarantineService, QuarantineService>();
            services.AddSingleton<ISecurityFindingService, SecurityFindingService>();
            services.AddSingleton<IFileScanner, FileScannerService>();
            services.AddSingleton<IScanCoordinatorService, ScanCoordinatorService>();
            services.AddSingleton<AegisPC.Contracts.Services.IStartupSecuritySweepService, AegisPC.Security.Scanning.StartupSecuritySweepService>();
            services.AddSingleton<IReputationService, ReputationService>();
            services.AddSingleton<ArchiveSafetyScanner>();
            services.AddSingleton<IBehaviorEngine, AegisPC.Security.RealTime.BehaviorEngine>();
            services.AddSingleton<AegisPC.Security.RealTime.IRealTimeProtectionEngine, AegisPC.Security.RealTime.RealTimeProtectionEngine>();
            services.AddSingleton<AegisPC.Security.RealTime.IBackgroundProtectionService, AegisPC.Security.RealTime.BackgroundProtectionService>();
            services.AddSingleton<AegisPC.Security.RealTime.IRansomwareProtectionEngine, AegisPC.Security.RealTime.RansomwareProtectionEngine>();
            services.AddSingleton<IAmsiScanService, AegisPC.Security.Scanning.AmsiScanService>();
            services.AddSingleton<AegisPC.Contracts.Services.IEtwProcessMonitorService, AegisPC.Security.RealTime.EtwProcessMonitorService>();
            services.AddSingleton<AegisPC.Contracts.AntiEvasion.IMemoryPatternScanner, AegisPC.Security.AntiEvasion.MemoryPatternScanner>();
            services.AddSingleton<IWebShieldService, WebShieldService>();
            services.AddSingleton<IDnsProtectionService, AegisPC.Security.RealTime.DnsProtectionService>();
            services.AddSingleton<AegisPC.Contracts.Services.IWindowsToastNotificationService, AegisPC.App.Services.WindowsToastNotificationService>();
            services.AddSingleton<AegisPC.Contracts.Services.INotificationAggregator, AegisPC.Security.Notifications.NotificationAggregator>();

            // Performance & Process Services
            services.AddSingleton<AegisPC.Performance.Hardware.IHardwareInfoService, AegisPC.Performance.Hardware.HardwareInfoService>();
            services.AddSingleton<IPerformanceMonitor, PerformanceMonitorService>();
            services.AddSingleton<IProcessMonitor, ProcessMonitorService>();
            services.AddSingleton<ProcessTerminationService>();
            services.AddSingleton<INetworkMonitor, NetworkMonitorService>();

            // Diagnostics Services
            services.AddSingleton<IWindowsEventAnalyzer, WindowsEventAnalyzer>();
            services.AddSingleton<ICorrelationEngine, CorrelationEngine>();
            services.AddSingleton<ICrashAnalyzer, CrashAnalyzer>();

            // Persistence & Startup Services
            services.AddSingleton<IStartupAnalyzer, StartupAnalyzerService>();
            services.AddSingleton<StartupManagementService>();

            // Browser Security Services
            services.AddSingleton<IBrowserSecurityScanner, BrowserSecurityService>();

            // Recommendations & Health Scoring Services
            services.AddSingleton<IRecommendationEngine, RecommendationEngine>();
            services.AddSingleton<HealthScoringEngine>();
            services.AddSingleton<IAiExplanationService, AiExplanationService>();

            // ViewModels (Singletons so state, active scans, and loaded data are preserved during navigation)
            services.AddSingleton<MainViewModel>();
            services.AddSingleton<DashboardViewModel>();
            services.AddSingleton<SecurityViewModel>();
            services.AddSingleton<ScanViewModel>();
            services.AddSingleton<RealTimeMonitorViewModel>();
            services.AddSingleton<ProcessListViewModel>();
            services.AddSingleton<PerformanceViewModel>();
            services.AddSingleton<NetworkViewModel>();
            services.AddSingleton<StartupManagerViewModel>();
            services.AddSingleton<ApplicationsViewModel>();
            services.AddSingleton<BrowserSecurityViewModel>();
            services.AddSingleton<WindowsEventsViewModel>();
            services.AddSingleton<CrashAnalysisViewModel>();
            services.AddSingleton<QuarantineViewModel>();
            services.AddSingleton<RecommendationsViewModel>();
            services.AddSingleton<HistoryViewModel>();
            services.AddSingleton<SettingsViewModel>();
            services.AddSingleton<RansomwareShieldViewModel>();
            services.AddSingleton<NetworkProtectionViewModel>();
            services.AddSingleton<ParentalControlsViewModel>();
            services.AddSingleton<IncidentCenterViewModel>();

            // Views
            services.AddTransient<DashboardView>();
            services.AddTransient<SecurityView>();
            services.AddTransient<ScanView>();
            services.AddTransient<RealTimeMonitorView>();
            services.AddTransient<ProcessListView>();
            services.AddTransient<PerformanceView>();
            services.AddTransient<NetworkView>();
            services.AddTransient<StartupManagerView>();
            services.AddTransient<ApplicationsView>();
            services.AddTransient<BrowserSecurityView>();
            services.AddTransient<WindowsEventsView>();
            services.AddTransient<CrashAnalysisView>();
            services.AddTransient<QuarantineView>();
            services.AddTransient<RecommendationsView>();
            services.AddTransient<HistoryView>();
            services.AddTransient<SettingsView>();
            services.AddTransient<RansomwareShieldView>();
            services.AddTransient<NetworkProtectionView>();
            services.AddTransient<ParentalControlsView>();
            services.AddTransient<IncidentCenterView>();

            // Service IPC & Tray
            services.AddSingleton<AegisPC.ServiceContracts.IServiceIpcClient, AegisPC.App.Services.ServiceIpcClient>();
            services.AddSingleton<AegisPC.App.Services.ISystemTrayService, AegisPC.App.Services.SystemTrayService>();
        }
    }
}
