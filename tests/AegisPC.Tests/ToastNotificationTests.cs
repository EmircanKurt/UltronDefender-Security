using System;
using AegisPC.App.Views;
using Xunit;

namespace AegisPC.Tests
{
    public class ToastNotificationTests
    {
        [Theory]
        [InlineData("🚨 Tehdit Engellendi", "Tehdit Engellendi")]
        [InlineData("🛡️ Sistem Korundu", "Sistem Korundu")]
        [InlineData("⚠️ Dikkat", "Dikkat")]
        [InlineData("", "Tehdit engellendi")]
        [InlineData("   ", "Tehdit engellendi")]
        public void CleanTitle_StripsEmojisProperly(string rawTitle, string expectedTitle)
        {
            string cleaned = ToastNotificationWindow.CleanTitle(rawTitle);
            Assert.Equal(expectedTitle, cleaned);
        }

        [Theory]
        [InlineData("🛡️ Tehdit Engellendi ve Karantinaya Alındı", "Zararlı dosya AES-256 kasaya kilitlendi.", "Danger", typeof(QuarantineView))]
        [InlineData("⚠️ Şüpheli Dosya Uyarısı", "Dosya şüpheli bulundu.", "Warning", typeof(IncidentCenterView))]
        [InlineData("Ultron Defender", "Dosya uyarıldı, olay merkezine kaydedildi.", "Warning", typeof(IncidentCenterView))]
        [InlineData("Tarama Tamamlandı", "Sistem taraması bitti", "Info", typeof(ScanView))]
        [InlineData("Zararlı Web Sitesi", "DNS koruması engelledi", "Warning", typeof(BrowserSecurityView))]
        [InlineData("Şüpheli Süreç", "powershell.exe injection denemesi", "Warning", typeof(ProcessListView))]
        [InlineData("Sistem Çökme Analizi", "Mavi ekran minidump incelendi", "Info", typeof(CrashAnalysisView))]
        public void ResolveTargetPage_RoutesToCorrectPage(string title, string message, string type, Type expectedPage)
        {
            Type resolved = ToastNotificationWindow.ResolveTargetPage(title, message, type);
            Assert.Equal(expectedPage, resolved);
        }
    }
}
