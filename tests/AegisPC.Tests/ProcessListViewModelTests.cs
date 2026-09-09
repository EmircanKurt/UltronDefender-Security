using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Xunit;

namespace AegisPC.Tests
{
    public class ProcessListViewModelTests
    {
        [Fact]
        public void DefaultState_HideWindowsServices_IsTrue()
        {
            var vm = new ProcessListViewModel();
            Assert.True(vm.HideWindowsServices, "HideWindowsServices must be true by default.");
        }

        [Fact]
        public void Constructor_LoadsHideWindowsServices_FromSettings()
        {
            var settings = new MemoryTestSettingsService();
            settings.SetSetting("ProcessManager_HideWindowsServices", false);

            var vm = new ProcessListViewModel(settingsService: settings);
            Assert.False(vm.HideWindowsServices, "HideWindowsServices must load false from settings.");
        }

        [Fact]
        public void HideWindowsServices_WhenChanged_PersistsToSettings()
        {
            var settings = new MemoryTestSettingsService();
            var vm = new ProcessListViewModel(settingsService: settings);

            Assert.True(vm.HideWindowsServices);

            // Toggle to false
            vm.HideWindowsServices = false;

            Assert.False(settings.GetSetting<bool>("ProcessManager_HideWindowsServices", true));
            Assert.True(settings.SaveCalledCount > 0, "SaveAsync must be called when setting changes.");

            // Toggle back to true
            vm.HideWindowsServices = true;

            Assert.True(settings.GetSetting<bool>("ProcessManager_HideWindowsServices", false));
        }

        [Theory]
        [InlineData("smss.exe")]
        [InlineData("csrss.exe")]
        [InlineData("wininit.exe")]
        [InlineData("services.exe")]
        [InlineData("lsass.exe")]
        [InlineData("svchost.exe")]
        [InlineData("fontdrvhost.exe")]
        [InlineData("dwm.exe")]
        [InlineData("spoolsv.exe")]
        [InlineData("taskhostw.exe")]
        [InlineData("sihost.exe")]
        [InlineData("ctfmon.exe")]
        [InlineData("SearchHost.exe")]
        [InlineData("SearchIndexer.exe")]
        [InlineData("SecurityHealthService.exe")]
        [InlineData("MsMpEng.exe")]
        [InlineData("WmiPrvSE.exe")]
        [InlineData("RuntimeBroker.exe")]
        [InlineData("smartscreen.exe")]
        [InlineData("TrustedInstaller.exe")]
        public void IsWindowsServiceOrSystem_IdentifiesKnownServices(string processName)
        {
            var proc = new ProcessInfo
            {
                PID = 1234,
                Name = processName,
                SessionId = 1,
                ExecutablePath = $@"C:\Windows\System32\{processName}"
            };

            bool isService = ProcessListViewModel.IsWindowsServiceOrSystem(proc);
            Assert.True(isService, $"{processName} should be identified as Windows service/system process.");
        }

        [Fact]
        public void IsWindowsServiceOrSystem_IdentifiesSession0Processes()
        {
            var proc = new ProcessInfo
            {
                PID = 999,
                Name = "custom_background_worker.exe",
                SessionId = 0,
                ExecutablePath = @"C:\CustomServices\worker.exe"
            };

            bool isService = ProcessListViewModel.IsWindowsServiceOrSystem(proc);
            Assert.True(isService, "Any process in Session 0 must be identified as Windows background service.");
        }

        [Fact]
        public void IsWindowsServiceOrSystem_IdentifiesMicrosoftSystem32Binaries()
        {
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var proc = new ProcessInfo
            {
                PID = 2000,
                Name = "devicecensus.exe",
                SessionId = 1,
                ExecutablePath = Path.Combine(winDir, "System32", "devicecensus.exe"),
                Publisher = "Microsoft Windows Publisher"
            };

            bool isService = ProcessListViewModel.IsWindowsServiceOrSystem(proc);
            Assert.True(isService, "Microsoft signed binary in System32 must be treated as system service.");
        }

        [Fact]
        public void IsWindowsServiceOrSystem_AllowsUserApplications()
        {
            var userApp = new ProcessInfo
            {
                PID = 5432,
                Name = "Notepad.exe",
                SessionId = 1,
                ExecutablePath = @"C:\Users\PC\AppData\Local\Programs\CustomApp\Notepad.exe",
                Publisher = "Independent Dev"
            };

            bool isService = ProcessListViewModel.IsWindowsServiceOrSystem(userApp);
            Assert.False(isService, "User applications outside System32 / Session 0 must not be flagged as system services.");
        }

        [Fact]
        public void IsWindowsServiceOrSystem_HandlesNullGracefully()
        {
            Assert.False(ProcessListViewModel.IsWindowsServiceOrSystem(null!));
        }

        private class MemoryTestSettingsService : ISettingsService
        {
            private readonly System.Collections.Generic.Dictionary<string, object?> _settings = new();
            public int SaveCalledCount { get; private set; }

            public T? GetSetting<T>(string key, T defaultValue)
            {
                if (_settings.TryGetValue(key, out var val) && val is T typed)
                {
                    return typed;
                }
                return defaultValue;
            }

            public void SetSetting<T>(string key, T value)
            {
                _settings[key] = value;
            }

            public Task SaveAsync(CancellationToken cancellationToken = default)
            {
                SaveCalledCount++;
                return Task.CompletedTask;
            }

            public Task LoadAsync(CancellationToken cancellationToken = default)
            {
                return Task.CompletedTask;
            }
        }
    }
}
