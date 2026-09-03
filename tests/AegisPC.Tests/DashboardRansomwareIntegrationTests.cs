using System;
using System.IO;
using System.Threading;
using AegisPC.App.ViewModels;
using AegisPC.App.Views;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class DashboardRansomwareIntegrationTests : IDisposable
    {
        private readonly string _testDir;
        private readonly RansomwareProtectionEngine _engine;

        public DashboardRansomwareIntegrationTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "DashboardRansomwareTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);

            _engine = new RansomwareProtectionEngine(null);
            foreach (var dir in _engine.ProtectedDirectories)
            {
                _engine.RemoveProtectedDirectory(dir);
            }
            _engine.AddProtectedDirectory(_testDir);
        }

        public void Dispose()
        {
            _engine.StopShield();
            if (Directory.Exists(_testDir))
            {
                try { Directory.Delete(_testDir, true); } catch { }
            }
        }

        [Fact]
        public void DashboardRansomwareToggle_PhysicallyControlsEngine_AndCreatesOrCleansCanary()
        {
            var canaryPath = Path.Combine(_testDir, "!_ultron_shield_canary.docx");

            // 1. Initially stopped
            Assert.False(_engine.IsShieldActive);
            Assert.False(File.Exists(canaryPath));

            // 2. Instantiate ViewModel with the engine
            var vm = new DashboardViewModel(ransomwareEngine: _engine);

            // 3. Toggle ON via ViewModel
            vm.IsRansomwareEnabled = true;

            // Assert engine is running and physical canary decoy file was deployed
            Assert.True(_engine.IsShieldActive, "Ransomware engine should be active when IsRansomwareEnabled is true.");
            Assert.True(File.Exists(canaryPath), "Physical canary file must exist on disk when ransomware shield is active.");
            Assert.Equal("Açık", vm.RansomwareStatusText);
            Assert.Equal("#4CAF50", vm.RansomwareStatusColor);

            // 4. Toggle OFF via ViewModel
            vm.IsRansomwareEnabled = false;

            // Assert engine is stopped and canary decoy file was cleaned up from disk
            Assert.False(_engine.IsShieldActive, "Ransomware engine should be stopped when IsRansomwareEnabled is false.");
            Assert.False(File.Exists(canaryPath), "Physical canary file must be removed from disk when shield is stopped.");
            Assert.Equal("Kapalı", vm.RansomwareStatusText);
            Assert.Equal("#94A3B8", vm.RansomwareStatusColor);
        }

        [Fact]
        public void DashboardRansomwareCommands_CanExecuteProperly()
        {
            var vm = new DashboardViewModel(ransomwareEngine: _engine);
            Assert.True(vm.OpenRansomwareSettingsCommand.CanExecute(null));
            Assert.True(vm.ToggleRansomwareProtectionCommand.CanExecute(null));

            var initialState = vm.IsRansomwareEnabled;
            vm.ToggleRansomwareProtectionCommand.Execute(null);
            Assert.Equal(!initialState, vm.IsRansomwareEnabled);
        }
    }
}
