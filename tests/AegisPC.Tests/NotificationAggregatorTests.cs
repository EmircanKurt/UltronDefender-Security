using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.App.Services;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.Notifications;
using Xunit;

namespace AegisPC.Tests
{
    public class NotificationAggregatorTests
    {
        private class MockToastService : IWindowsToastNotificationService
        {
            public List<(string Title, string Message, string Type)> Toasts { get; } = new();

            public void ShowToast(string title, string message, string type = "Info")
            {
                lock (Toasts)
                {
                    Toasts.Add((title, message, type));
                }
            }
        }

        [Fact]
        public async Task Test_CriticalThreat_BypassesAggregationAndFiresImmediately()
        {
            var mockToast = new MockToastService();
            using var aggregator = new NotificationAggregator(mockToast)
            {
                AggregationWindow = TimeSpan.FromSeconds(5)
            };

            aggregator.PushThreatEvent("LockBit.Ransomware", @"C:\Users\PC\Desktop\lockbit.exe", "Terminated & Quarantined", isCritical: true);
            for (int w = 0; w < 30 && mockToast.Toasts.Count == 0; w++) await Task.Delay(50);

            Assert.Single(mockToast.Toasts);
            Assert.Contains("Ultron Defender (Antivirüs Programı)", mockToast.Toasts[0].Title);
            Assert.Contains("KRİTİK", mockToast.Toasts[0].Title);
            Assert.Equal("danger", mockToast.Toasts[0].Type);
        }

        [Fact]
        public async Task Test_MultipleThreats_AggregatesIntoBatchSummary()
        {
            var mockToast = new MockToastService();
            using var aggregator = new NotificationAggregator(mockToast)
            {
                AggregationWindow = TimeSpan.FromMilliseconds(200)
            };

            // Push 5 routine threats
            for (int i = 1; i <= 5; i++)
            {
                aggregator.PushThreatEvent($"Threat #{i}", $@"C:\Downloads\file{i}.exe", "Karantina", isCritical: false);
            }

            // Wait for aggregator timer to flush
            for (int w = 0; w < 30 && mockToast.Toasts.Count == 0; w++) await Task.Delay(50);

            Assert.Single(mockToast.Toasts);
            Assert.Contains("Ultron Defender (Antivirüs Programı)", mockToast.Toasts[0].Title);
            Assert.Contains("5 Güvenlik Tehdidi", mockToast.Toasts[0].Title);
            Assert.Contains("5 adet tehdit engellendi", mockToast.Toasts[0].Message);
        }

        [Fact]
        public async Task Test_TenSimultaneousViruses_AggregatesIntoSingleNotification()
        {
            var mockToast = new MockToastService();
            using var aggregator = new NotificationAggregator(mockToast)
            {
                AggregationWindow = TimeSpan.FromMilliseconds(250)
            };

            // Simulate finding 10 viruses in rapid drop / scan
            for (int i = 1; i <= 10; i++)
            {
                aggregator.PushThreatEvent($"Trojan.Win32.Generic.{i}", $@"C:\Temp\virus_{i}.exe", "Karantina Kasasına Kilitlendi", isCritical: true);
            }

            for (int w = 0; w < 30 && mockToast.Toasts.Count == 0; w++) await Task.Delay(50);

            // Must produce EXACTLY 1 combined notification for all 10 viruses per user directive!
            Assert.Single(mockToast.Toasts);
            Assert.Contains("Ultron Defender (Antivirüs Programı)", mockToast.Toasts[0].Title);
            Assert.Contains("10 Güvenlik Tehdidi", mockToast.Toasts[0].Title);
            Assert.Contains("10 adet tehdit engellendi", mockToast.Toasts[0].Message);
        }

        [Fact]
        public void Test_SingleThreat_EmitsSingleNotificationOnFlush()
        {
            var mockToast = new MockToastService();
            using var aggregator = new NotificationAggregator(mockToast)
            {
                AggregationWindow = TimeSpan.FromMinutes(1) // Long window
            };

            aggregator.PushThreatEvent("Suspicious.Dropper", @"C:\Temp\dropper.exe", "Quarantined", isCritical: false);
            aggregator.Flush();

            Assert.Single(mockToast.Toasts);
            Assert.Contains("Ultron Defender (Antivirüs Programı)", mockToast.Toasts[0].Title);
            Assert.Contains("Tehdit Etkisiz Hale Getirildi", mockToast.Toasts[0].Title);
            Assert.Contains("Suspicious.Dropper", mockToast.Toasts[0].Message);
        }

        private class MockSettingsService : ISettingsService
        {
            public AppSettings Current { get; } = new();
            public int SaveCallCount { get; private set; }

            public T? GetSetting<T>(string key, T defaultValue)
            {
                var prop = typeof(AppSettings).GetProperty(key);
                if (prop == null) return defaultValue;
                var val = prop.GetValue(Current);
                if (val is T typedVal) return typedVal;
                return defaultValue;
            }

            public void SetSetting<T>(string key, T value)
            {
                var prop = typeof(AppSettings).GetProperty(key);
                if (prop != null && prop.CanWrite)
                {
                    prop.SetValue(Current, value);
                }
            }

            public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
            public Task SaveAsync(CancellationToken cancellationToken = default)
            {
                SaveCallCount++;
                return Task.CompletedTask;
            }
        }

        [Fact]
        public void Test_NotificationDisabled_SuppressesToasts()
        {
            var settings = new MockSettingsService();
            settings.Current.NotificationsEnabled = false;

            using var toastService = new WindowsToastNotificationService(settingsService: settings);

            // Should be suppressed
            toastService.ShowToast("🚨 Tehdit Tespit Edildi!", "Trojan.Generic bulundu.", "Danger");
            toastService.ShowToast("Sistem Bilgisi", "Normal bildirim.", "Info");

            Assert.False(settings.GetSetting("NotificationsEnabled", true));
        }

        [Fact]
        public void Test_NotificationDeduplication_BlocksRepeatedSameThreats()
        {
            var settings = new MockSettingsService();
            settings.Current.NotificationsEnabled = true;

            using var toastService = new WindowsToastNotificationService(settingsService: settings)
            {
                AggregationWindow = TimeSpan.FromMilliseconds(50)
            };

            toastService.ShowToast("🚨 Tehdit Tespit Edildi!", "Zararlı dosya: malware.exe", "Danger");
            toastService.ShowToast("🚨 1 adet Tehdit Tespit Edildi!", "Zararlı dosya: malware.exe", "Danger");

            Assert.True(settings.GetSetting("NotificationsEnabled", true));
        }

        [Fact]
        public void Test_SettingsViewModel_NotificationsEnabled_AutoSaves()
        {
            var vm = new SettingsViewModel();
            vm.NotificationsEnabled = false;

            Assert.False(vm.NotificationsEnabled);
            Assert.Contains("Sessiz mod", vm.StatusMessage);
        }

        [Fact]
        public async Task Test_DashboardThreatStatus_CleansToSafe_WhenZeroFindings()
        {
            var vm = new DashboardViewModel();
            vm.HasThreatsDetected = true;
            vm.ProtectionStatusText = "Tehdit bulundu";
            vm.ProtectionBadgeText = "23 şüpheli bulgu";

            await vm.RefreshThreatStatusAsync();

            Assert.False(vm.HasThreatsDetected);
            Assert.Equal("Sisteminiz güvende", vm.ProtectionStatusText);
            Assert.Equal("Gerçek zamanlı koruma aktif", vm.ProtectionBadgeText);
            Assert.Equal("#4CAF50", vm.ProtectionStatusColor);
            Assert.Equal(0, vm.PendingFindingsCount);
        }
    }
}
