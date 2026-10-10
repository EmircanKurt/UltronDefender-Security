using AegisPC.App.Services;
using AegisPC.Core.Models;
using AegisPC.ServiceContracts.IpcMessages;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert availability presentation tests, not protection effectiveness tests.</summary>
public sealed class PlainProtectionPresentationReviewTests
{
    private static readonly DateTime Now = new(2026, 10, 6, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>Unavailable observations cannot become green or enabled states.</summary>
    [Theory]
    [InlineData(false, 0, 1)] [InlineData(true, -16, 1)]
    [InlineData(true, 1, 1)] [InlineData(true, 0, 2)]
    public void MissingOrStaleObservationIsNotProtection(bool connected, int seconds, int version)
    {
        var status = Status(ProtectionHealthState.Healthy, seconds, version);
        var view = DashboardProtectionPresentation.Create(status, connected, Now);
        Assert.Equal("Koruma durumu alınamadı", view.Title);
        Assert.All(view.Rows.Take(4), row => Assert.Equal("Bilgi yok", row.State));
    }

    /// <summary>Old service contracts and absent status stay explicitly unknown.</summary>
    [Fact]
    public void MissingStatusAndHealthStayUnknown()
    {
        Assert.Contains("alınamadı", DashboardProtectionPresentation.Create(null, true, Now).Title);
        var status = new ProtectionStatus { ProtectionLevel = "Full", IsServiceRunning = true };
        Assert.Contains("alınamadı", DashboardProtectionPresentation.Create(status, true, Now).Title);
    }

    /// <summary>A configured switch does not prove a listener, device inventory or emergency Guardian.</summary>
    [Fact]
    public void DesiredSwitchDoesNotInventListenerCoverage()
    {
        var status = Status(ProtectionHealthState.Healthy);
        status.IsUltronAiEnabled = true;
        status.IsRansomwareShieldEnabled = true;
        var view = DashboardProtectionPresentation.Create(status, true, Now);
        Assert.Equal("Kapsam sınırlı", view.Rows[0].State);
        Assert.Equal("Yerel inceleme açık", view.Rows[1].State);
        Assert.Equal("Kapsam alınamadı", view.Rows[2].State);
        Assert.Equal("Bilgi yok", view.Rows[3].State);
        Assert.Equal("İstek üzerine inceleme", view.Rows[4].State);
    }

    /// <summary>Fresh device data is evaluated independently from the general heartbeat.</summary>
    [Theory]
    [InlineData(-16, "Bilgi yok")] [InlineData(1, "Bilgi yok")]
    [InlineData(0, "Gözlem etkin")]
    public void DeviceCaptureHasIndependentFreshness(int age, string expected)
    {
        var status = Status(ProtectionHealthState.Healthy);
        status.Health!.DeviceInventoryActive = true;
        status.Health.DeviceInventoryComplete = true;
        status.Health.DeviceInventoryCapturedAtUtc = Now.AddSeconds(age);
        Assert.Equal(expected, DashboardProtectionPresentation.Create(status, true, Now).Rows[3].State);
    }

    /// <summary>Observed loss is visible even if the latest listeners report healthy.</summary>
    [Fact]
    public void EventLossRemainsVisible()
    {
        var status = Status(ProtectionHealthState.Healthy);
        status.Health!.FileWatcherErrors = 1;
        Assert.Equal("İzleme kapsamını inceleyin", DashboardProtectionPresentation.Create(status, true, Now).Title);
    }

    /// <summary>Fresh stopped state is distinguished from missing data.</summary>
    [Fact]
    public void StoppedStateIsNotUnknownOrActive()
    {
        var status = Status(ProtectionHealthState.Stopped);
        Assert.Equal("Durduruldu", DashboardProtectionPresentation.Create(status, true, Now).Rows[0].State);
        status.IsRealTimeEnabled = false;
        Assert.Equal("Kapalı", DashboardProtectionPresentation.Create(status, true, Now).Rows[0].State);
    }

    private static ProtectionStatus Status(ProtectionHealthState state, int seconds = 0, int version = 1) => new()
    {
        ProtectionLevel = "ConfiguredOnly", IsServiceRunning = true, IsRealTimeEnabled = true,
        Health = new ProtectionHealthSnapshot { State = state, CapturedAtUtc = Now.AddSeconds(seconds), ProtocolVersion = version }
    };
}
