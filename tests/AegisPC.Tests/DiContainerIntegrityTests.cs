using System;
using System.Linq;
using AegisPC.App.Startup;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AegisPC.Tests
{
    public class DiContainerIntegrityTests
    {
        [Fact]
        public void AllViewModelsAndSecurityServices_CanBeResolvedFromDiContainer()
        {
            var services = new ServiceCollection();
            ServiceRegistration.RegisterServices(services);
            var provider = services.BuildServiceProvider();

            // 1. Verify Core Security & Realtime Services
            Assert.NotNull(provider.GetRequiredService<IDnsProtectionService>());
            Assert.NotNull(provider.GetRequiredService<IWebShieldService>());
            Assert.NotNull(provider.GetRequiredService<AegisPC.Contracts.Detection.IDetectionHub>());
            Assert.NotNull(provider.GetRequiredService<IFileScanner>());
            Assert.NotNull(provider.GetRequiredService<IQuarantineService>());
            Assert.NotNull(provider.GetRequiredService<AegisPC.Security.RealTime.IRansomwareProtectionEngine>());

            // 2. Verify Every ViewModel
            var viewModels = new Type[]
            {
                typeof(MainViewModel),
                typeof(DashboardViewModel),
                typeof(SecurityViewModel),
                typeof(ScanViewModel),
                typeof(ProcessListViewModel),
                typeof(PerformanceViewModel),
                typeof(StartupManagerViewModel),
                typeof(ApplicationsViewModel),
                typeof(BrowserSecurityViewModel),
                typeof(WindowsEventsViewModel),
                typeof(CrashAnalysisViewModel),
                typeof(QuarantineViewModel),
                typeof(RecommendationsViewModel),
                typeof(HistoryViewModel),
                typeof(SettingsViewModel),
                typeof(RansomwareShieldViewModel),
                typeof(NetworkProtectionViewModel),
                typeof(ParentalControlsViewModel),
                typeof(IncidentCenterViewModel)
            };

            foreach (var vmType in viewModels)
            {
                var instance = provider.GetRequiredService(vmType);
                Assert.NotNull(instance);
            }
        }
    }
}
