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
using Serilog;

namespace AegisPC.App.Startup
{
    public static class ServiceRegistration
    {
        public static void RegisterServices(IServiceCollection services)
        {
            // Core Logging Infrastructure
            services.AddLogging(builder => builder.AddSerilog(Serilog.Log.Logger, dispose: false));

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
            services.AddSingleton<IProtectionDisableConfirmation, ProtectionDisableConfirmation>();
            services.AddSingleton<UltronAiServicePreferenceSync>();
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
            services.AddSingleton<AegisPC.Contracts.Detection.IUltronAiEngine, AegisPC.Security.UltronAI.UltronAiEngine>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin>(sp =>
                new AegisPC.Security.Detection.Detectors.UltronAiDetectorPlugin(
                    sp.GetRequiredService<AegisPC.Contracts.Detection.IUltronAiEngine>(),
                    () => sp.GetRequiredService<ISettingsService>().GetSetting("IsUltronAiEnabled", true)));
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
            services.AddSingleton<AegisPC.Security.Detection.YaraEngine.IYaraEngine, AegisPC.Security.Detection.YaraEngine.YaraEngine>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.YaraDetector>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectionHub>(sp => AegisPC.Security.Detection.DetectionHubFactory.CreateDefault(
                sp.GetRequiredService<IHashService>(), sp.GetRequiredService<ISignatureVerifier>(),
                yaraEngine: sp.GetRequiredService<AegisPC.Security.Detection.YaraEngine.IYaraEngine>(),
                reputationService: sp.GetService<IReputationService>(), exclusionService: sp.GetRequiredService<IExclusionService>(),
                amsiScanService: sp.GetRequiredService<IAmsiScanService>(),
                isUltronAiEnabled: () => sp.GetRequiredService<ISettingsService>().GetSetting("IsUltronAiEnabled", true)));
            services.AddSingleton<AegisPC.Security.UltronAI.PilotGatedActionAdapter>();
            services.AddSingleton<AegisPC.Contracts.Protection.IProtectionActionBroker>(sp =>
                new AegisPC.Security.UltronAI.ProtectionActionBroker(
                    sp.GetRequiredService<AegisPC.Security.UltronAI.PilotGatedActionAdapter>(),
                    sp.GetRequiredService<AegisPC.Security.UltronAI.PilotGatedActionAdapter>()));
            services.AddSingleton<AegisPC.Core.Localization.ILocalizationService>(AegisPC.Core.Localization.LocalizationService.Instance);
            services.AddSingleton<IExclusionService, AegisPC.Security.Safety.ExclusionService>();
            services.AddSingleton<IAllowlistService, AllowlistService>();
            services.AddSingleton<AegisPC.Contracts.Services.ISignatureVerifier, AegisPC.Security.Scanning.SignatureVerifier>();
            services.AddSingleton<AegisPC.Contracts.Safety.IProtectedPathGuard, AegisPC.Security.Safety.ProtectedPathGuard>();
            services.AddSingleton<AegisPC.Contracts.Safety.IReparsePointGuard, AegisPC.Security.Safety.ReparsePointGuard>();
            services.AddSingleton<AegisPC.Contracts.Policy.IPolicyEngine, AegisPC.Security.Policy.PolicyEngine>();
            services.AddSingleton<AegisPC.Security.Scanning.IFileHashMatcher, AegisPC.Security.Scanning.FileHashMatcher>();
            services.AddSingleton<IQuarantineService, AegisPC.App.Services.ServiceQuarantineClient>();
            services.AddSingleton<IFileContentClassifier, FileContentClassifier>();
            services.AddSingleton<IScanTargetResolver, WindowsScanTargetResolver>();
            services.AddSingleton<IScanVolumeTargetResolver, WindowsScanVolumeTargetResolver>();
            services.AddSingleton<ISecurityFindingService, SecurityFindingService>();
            services.AddSingleton<IScanResourceManager, AdaptiveScanResourceManager>();
            services.AddSingleton<IScanSessionManager, ScanSessionManager>();
            services.AddSingleton<IFileScanner>(sp => new FileScannerService(
                new DirectoryWalker(sp.GetRequiredService<IScanTargetResolver>(), sp.GetRequiredService<IScanVolumeTargetResolver>()), new ScanQueueCoordinator(sp.GetRequiredService<IScanResourceManager>()),
                sp.GetRequiredService<AegisPC.Security.Scanning.IFileHashMatcher>(),
                new PupAnalysisCoordinator(sp.GetRequiredService<AegisPC.Contracts.Detection.IDetectionHub>(), sp.GetRequiredService<ISecurityFindingService>()),
                sp.GetRequiredService<ArchiveSafetyScanner>(), sp.GetRequiredService<ISecurityFindingService>(),
                sp.GetService<Microsoft.Extensions.Logging.ILogger<FileScannerService>>(), sp.GetRequiredService<IFileContentClassifier>()));
            services.AddSingleton<ScanCoordinatorService>();
            services.AddSingleton<IScanCoordinatorService>(sp => sp.GetRequiredService<ScanCoordinatorService>());
            services.AddSingleton<IBackgroundScanCoordinator>(sp => sp.GetRequiredService<ScanCoordinatorService>());
            services.AddSingleton<AegisPC.Contracts.Services.IStartupSecuritySweepService, AegisPC.Security.Scanning.StartupSecuritySweepService>();
            services.AddSingleton<IReputationService, ReputationService>();
            services.AddSingleton<ArchiveSafetyScanner>();
            services.AddSingleton<IBehaviorEngine, AegisPC.Security.RealTime.BehaviorEngine>();
            services.AddSingleton<AegisPC.Security.RealTime.IRealTimeProtectionEngine>(sp => new AegisPC.Security.RealTime.RealTimeProtectionEngine(
                sp.GetRequiredService<IFileScanner>(), sp.GetRequiredService<IHashService>(), sp.GetRequiredService<ISignatureVerifier>(), sp.GetRequiredService<IRiskScoringEngine>(),
                sp.GetRequiredService<IQuarantineService>(), sp.GetRequiredService<ISecurityFindingService>(),
                sp.GetService<IAuditLogService>(), sp.GetService<IReputationService>(),
                sp.GetService<Microsoft.Extensions.Logging.ILogger<AegisPC.Security.RealTime.RealTimeProtectionEngine>>(), sp.GetRequiredService<IExclusionService>(),
                () => sp.GetRequiredService<ISettingsService>().GetSetting("EnableAutoQuarantine", true),
                () => sp.GetRequiredService<ISettingsService>().GetSetting("AutoQuarantineThreshold", 85),
                detectionHub: sp.GetRequiredService<AegisPC.Contracts.Detection.IDetectionHub>(),
                backgroundResources: sp.GetRequiredService<IScanResourceManager>(),
                scanTargets: sp.GetRequiredService<IScanTargetResolver>()));
            services.AddSingleton<AegisPC.Security.RealTime.IBackgroundProtectionService, AegisPC.Security.RealTime.BackgroundProtectionService>();
            services.AddSingleton<AegisPC.Security.RealTime.IRansomwareProtectionEngine, AegisPC.App.Services.ServiceRansomwareClient>();
            services.AddSingleton<IAmsiScanService, AegisPC.Security.Scanning.AmsiScanService>();
            services.AddSingleton<AegisPC.Contracts.Detection.IDetectorPlugin, AegisPC.Security.Detection.Detectors.AmsiContentDetector>();
            services.AddSingleton<AegisPC.Contracts.Services.IEtwProcessMonitorService, AegisPC.Security.RealTime.EtwProcessMonitorService>();
            services.AddSingleton<IEtwPreExecProtectionService>(sp => new AegisPC.Security.RealTime.EtwPreExecProtectionService(
                sp.GetRequiredService<AegisPC.Contracts.Detection.IDetectionHub>(), sp.GetRequiredService<IRiskScoringEngine>(), sp.GetRequiredService<ISignatureVerifier>(),
                quarantineService: sp.GetRequiredService<IQuarantineService>(), auditLogService: sp.GetService<IAuditLogService>(),
                logger: sp.GetService<Microsoft.Extensions.Logging.ILogger<AegisPC.Security.RealTime.EtwPreExecProtectionService>>(), exclusionService: sp.GetRequiredService<IExclusionService>(),
                enableAutoQuarantine: () => sp.GetRequiredService<ISettingsService>().GetSetting("EnableAutoQuarantine", true),
                autoQuarantineThreshold: () => sp.GetRequiredService<ISettingsService>().GetSetting("AutoQuarantineThreshold", 85)));
            services.AddSingleton<AegisPC.Contracts.AntiEvasion.IMemoryPatternScanner, AegisPC.Security.AntiEvasion.MemoryPatternScanner>();
            services.AddSingleton<IWebShieldService, WebShieldService>();
            services.AddSingleton<IDnsProtectionService, AegisPC.Security.RealTime.DnsProtectionService>();
            services.AddSingleton<AegisPC.Contracts.Services.IWindowsToastNotificationService, AegisPC.App.Services.WindowsToastNotificationService>();
            services.AddSingleton<AegisPC.Contracts.Services.INotificationAggregator, AegisPC.Security.Notifications.NotificationAggregator>();
            services.AddSingleton<AegisPC.Contracts.Services.IScanSchedulerEnvironmentProvider, AegisPC.Infrastructure.Platform.WindowsScanSchedulerEnvironmentProvider>();
            services.AddSingleton<AegisPC.Contracts.Services.IQuarantineUndoLogService, AegisPC.Security.Safety.QuarantineUndoLogService>();
            services.AddSingleton<AegisPC.Contracts.Services.ILocalReputationService, AegisPC.Security.Reputation.LocalReputationService>();
            services.AddSingleton<AegisPC.Contracts.Services.IIncidentTimelineExporter, AegisPC.Security.Diagnostics.IncidentTimelineExporter>();
            services.AddSingleton<AegisPC.Contracts.Services.IDuplicateExecutableDetector, AegisPC.Infrastructure.Platform.DuplicateExecutableDetector>();

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

            // ViewModels:
            // 1. Core State & Koordinatör ViewModels (Sayfalar arası gezinmede durumun korunması için Singleton)
            services.AddSingleton<MainViewModel>();
            services.AddSingleton<DashboardViewModel>();
            services.AddSingleton<SecurityViewModel>();
            services.AddSingleton<ScanViewModel>();
            services.AddSingleton<SettingsViewModel>();
            services.AddSingleton<RansomwareShieldViewModel>();
            services.AddSingleton<NetworkProtectionViewModel>();
            services.AddSingleton<ParentalControlsViewModel>();
            services.AddSingleton<QuarantineViewModel>();

            // 2. Ağır Veri/Olay Tutan Teşhis ViewModels (Her sayfa açılışında taze veri, ayrılınca GC temizliği için Transient)
            services.AddTransient<ProcessListViewModel>();
            services.AddTransient<PerformanceViewModel>();
            services.AddTransient<StartupManagerViewModel>();
            services.AddTransient<ApplicationsViewModel>();
            services.AddTransient<BrowserSecurityViewModel>();
            services.AddTransient<WindowsEventsViewModel>();
            services.AddTransient<CrashAnalysisViewModel>();
            services.AddTransient<RecommendationsViewModel>();
            services.AddTransient<HistoryViewModel>();
            services.AddTransient<IncidentCenterViewModel>();
            services.AddTransient<UltronProtectionCentreViewModel>();

            // Views
            services.AddTransient<DashboardView>();
            services.AddTransient<SecurityView>();
            services.AddTransient<ScanView>();
            services.AddTransient<ProcessListView>();
            services.AddTransient<PerformanceView>();
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
            services.AddTransient<RansomwareSettingsWindow>();
            services.AddTransient<NetworkProtectionView>();
            services.AddTransient<ParentalControlsView>();
            services.AddTransient<IncidentCenterView>();
            services.AddTransient<UltronProtectionCentreView>();
            services.AddTransient<SplashWindow>();

            // Service IPC & Tray
            services.AddSingleton<AegisPC.ServiceContracts.IServiceIpcClient, AegisPC.App.Services.ServiceIpcClient>();
            services.AddSingleton<AegisPC.App.Services.ISystemTrayService, AegisPC.App.Services.SystemTrayService>();
        }
    }
}
