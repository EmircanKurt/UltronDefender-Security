using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using AegisPC.App.Services;
using AegisPC.Contracts.Services;
using AegisPC.Security.Notifications;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks notification wording and lifecycle without native windows or real detections.</summary>
public sealed class NotificationTruthRegressionTests
{
    [Fact]
    public void RawWarningsAndFailures_AreNotificationsNotThreeViruses()
    {
        var sink = new RecordingToastService();
        using var service = CreateToast(sink);
        service.ShowToast("Tarama eksik", "3 dosya okunamadı.", "Warning");
        service.ShowToast("Karantina hatası", "Dosya karantinaya alınamadı.", "Error");
        service.ShowToast("Servis bağlantısı", "Bağlantı kesildi.", "Danger");

        FlushToast(service);

        var toast = Assert.Single(sink.Toasts);
        Assert.Contains("3 bildirim", toast.Title);
        Assert.Contains("Dosya karantinaya alınamadı.", toast.Message);
        Assert.Contains("3 dosya okunamadı.", toast.Message);
        AssertNoInventedOutcome(toast);
    }

    [Fact]
    public void DistinctPathsWithDigits_AreNotMergedByDigitStripping()
    {
        var sink = new RecordingToastService();
        using var service = CreateToast(sink);
        service.ShowToast("İnceleme uyarısı", @"Dosya C:\Mods\file1.jar incelenemedi.", "Warning");
        service.ShowToast("İnceleme uyarısı", @"Dosya C:\Mods\file2.jar incelenemedi.", "Warning");

        FlushToast(service);

        var toast = Assert.Single(sink.Toasts);
        Assert.Contains("2 bildirim", toast.Title);
        Assert.Contains("file1.jar", toast.Message);
        Assert.Contains("file2.jar", toast.Message);
    }

    [Fact]
    public void ConcurrentExactDuplicates_EmitOnlyOneNotification()
    {
        var sink = new RecordingToastService();
        using var service = CreateToast(sink);
        Parallel.For(0, 64, _ => service.ShowToast("Tarama uyarısı", "Dosya okunamadı.", "Warning"));

        FlushToast(service);

        var toast = Assert.Single(sink.Toasts);
        Assert.DoesNotContain("bildirim", toast.Title);
        Assert.Equal("Dosya okunamadı.", toast.Message);
    }

    [Fact]
    public void NewDistinctBatch_IsNotSuppressedByGlobalFifteenMinuteCooldown()
    {
        var sink = new RecordingToastService();
        using var service = CreateToast(sink);
        service.ShowToast("İlk uyarı", "Dosya1 okunamadı.", "Warning");
        service.ShowToast("İkinci uyarı", "Dosya2 okunamadı.", "Warning");
        FlushToast(service);
        service.ShowToast("Üçüncü uyarı", "Dosya3 okunamadı.", "Warning");
        service.ShowToast("Dördüncü uyarı", "Dosya4 okunamadı.", "Warning");
        FlushToast(service);

        Assert.Equal(2, sink.Toasts.Count);
    }

    [Fact]
    public void ToastDispose_DropsPendingAndFutureNotifications()
    {
        var sink = new RecordingToastService();
        var service = CreateToast(sink);
        service.ShowToast("İnceleme uyarısı", "İnceleme gerekli.", "Warning");

        service.Dispose();
        FlushToast(service);
        service.ShowToast("Kapanış sonrası", "Gösterilmemeli.", "Info");

        Assert.Empty(sink.Toasts);
    }

    [Fact]
    public void CriticalRecordedEvent_DoesNotInventBlockingSuccess()
    {
        var sink = new RecordingToastService();
        using var aggregator = CreateAggregator(sink);
        aggregator.PushThreatEvent("İnceleme bulgusu", @"C:\Mods\file1.jar", "İşlem başarısız", true);

        aggregator.Flush();

        var toast = Assert.Single(sink.Toasts);
        Assert.Contains("KRİTİK", toast.Title);
        Assert.Equal("danger", toast.Type);
        Assert.Contains("İşlem başarısız", toast.Message);
        AssertNoInventedOutcome(toast);
    }

    [Fact]
    public void FailedQuarantineAndUnresolvedEvents_AreNotReportedAsQuarantinedOrBlocked()
    {
        var sink = new RecordingToastService();
        using var aggregator = CreateAggregator(sink);
        aggregator.PushThreatEvent("Bulgu A", @"C:\Mods\file1.jar", "Karantinaya alınamadı");
        aggregator.PushThreatEvent("Bulgu B", @"C:\Mods\file2.jar", "Quarantine failed");
        aggregator.PushThreatEvent("Bulgu C", @"C:\Mods\file3.jar", "İnceleme bekliyor");

        aggregator.Flush();

        var toast = Assert.Single(sink.Toasts);
        Assert.Contains("3 güvenlik olayı", toast.Title);
        Assert.Contains("Karantinaya alınamadı", toast.Message);
        Assert.Contains("Quarantine failed", toast.Message);
        Assert.Contains("İnceleme bekliyor", toast.Message);
        AssertNoInventedOutcome(toast);
    }

    [Fact]
    public void RepeatedIdenticalEvent_IsCountedOnce()
    {
        var sink = new RecordingToastService();
        using var aggregator = CreateAggregator(sink);
        for (int i = 0; i < 3; i++)
            aggregator.PushThreatEvent("Aynı bulgu", @"C:\Mods\file1.jar", "İnceleme bekliyor");

        aggregator.Flush();

        var toast = Assert.Single(sink.Toasts);
        Assert.DoesNotContain("3", toast.Title);
        Assert.Equal(1, toast.Message.Split("Aynı bulgu", StringSplitOptions.None).Length - 1);
    }

    [Fact]
    public void DifferentPathsAndActions_RemainDistinctEvents()
    {
        var sink = new RecordingToastService();
        using var aggregator = CreateAggregator(sink);
        aggregator.PushThreatEvent("Aynı bulgu", @"C:\Mods\file1.jar", "İnceleme bekliyor");
        aggregator.PushThreatEvent("Aynı bulgu", @"C:\Mods\file2.jar", "İnceleme bekliyor");
        aggregator.PushThreatEvent("Aynı bulgu", @"C:\Mods\file2.jar", "İşlem başarısız");

        aggregator.Flush();

        Assert.Contains("3 güvenlik olayı", Assert.Single(sink.Toasts).Title);
    }

    [Fact]
    public void AggregatorDispose_DropsPendingAndFutureEvents()
    {
        var sink = new RecordingToastService();
        var aggregator = CreateAggregator(sink);
        aggregator.PushThreatEvent("Bulgu", @"C:\Mods\file1.jar", "İnceleme bekliyor");

        aggregator.Dispose();
        aggregator.Flush();
        aggregator.PushThreatEvent("Yeni bulgu", @"C:\Mods\file2.jar", "İnceleme bekliyor");
        aggregator.Flush();

        Assert.Empty(sink.Toasts);
    }

    [Fact]
    public void SingleSourceSuccess_IsPreservedWithoutGeneralizingToOtherEvents()
    {
        var sink = new RecordingToastService();
        using var service = CreateToast(sink);
        service.ShowToast("İşlem kaydı", "Dosya karantinaya alındı; kayıt kimliği: 321.", "Warning");

        FlushToast(service);

        Assert.Equal("Dosya karantinaya alındı; kayıt kimliği: 321.", Assert.Single(sink.Toasts).Message);
    }

    [Fact]
    public void RoutineScanFailure_IsNotSuppressedAsInformationalMaintenance()
    {
        var sink = new RecordingToastService();
        using var service = CreateToast(sink);
        service.ShowToast("Rutin Tarama", "Tarama tamamlanamadı; dosya okunamadı.", "Error");

        FlushToast(service);

        var toast = Assert.Single(sink.Toasts);
        Assert.Equal("Rutin Tarama", toast.Title);
        Assert.Equal("Tarama tamamlanamadı; dosya okunamadı.", toast.Message);
    }

    private static WindowsToastNotificationService CreateToast(RecordingToastService sink)
    {
        var constructor = typeof(WindowsToastNotificationService).GetConstructor(new[]
        {
            typeof(ISettingsService), typeof(ILogger<WindowsToastNotificationService>),
            typeof(Action<string, string, string>), typeof(bool)
        });
        Assert.NotNull(constructor);
        Action<string, string, string> callback = (title, message, type) => sink.ShowToast(title, message, type);
        return (WindowsToastNotificationService)constructor.Invoke(new object?[] { null, null, callback, false });
    }

    private static NotificationAggregator CreateAggregator(RecordingToastService sink)
    {
        var constructor = typeof(NotificationAggregator).GetConstructor(new[]
        {
            typeof(IWindowsToastNotificationService), typeof(ILogger<NotificationAggregator>), typeof(bool)
        });
        Assert.NotNull(constructor);
        return (NotificationAggregator)constructor.Invoke(new object?[] { sink, null, false });
    }

    private static void FlushToast(WindowsToastNotificationService service)
    {
        var method = typeof(WindowsToastNotificationService).GetMethod("FlushThreats", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(method);
        method.Invoke(service, null);
    }

    private static void AssertNoInventedOutcome((string Title, string Message, string Type) toast)
    {
        string content = toast.Title + " " + toast.Message;
        Assert.DoesNotContain("Tehdit Engellendi", content, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("etkisiz hale getirildi", content, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("adet tehdit engellendi", content, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("temizlenerek", content, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("işlem durduruldu", content, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("karantinaya alındı", content, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class RecordingToastService : IWindowsToastNotificationService
    {
        public List<(string Title, string Message, string Type)> Toasts { get; } = new();

        public void ShowToast(string title, string message, string type = "Info")
        {
            lock (Toasts) Toasts.Add((title, message, type));
        }
    }
}
