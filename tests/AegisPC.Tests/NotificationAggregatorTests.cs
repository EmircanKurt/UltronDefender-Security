using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
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
            await Task.Delay(450);

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
            await Task.Delay(350);

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

            await Task.Delay(500);

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
    }
}
